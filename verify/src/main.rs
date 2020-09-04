#![feature(assoc_char_funcs)]

use eyre::Report;
use common::voter::{VoterId, Vote};
use common::config::PapervoteConfig;
use common::APP_NAME;
use common::net::{Response, WrappedResponse, TrusteeMessage, TrusteeInfo};
use clap::{App, SubCommand};
use std::fmt::Display;
use serde::export::Formatter;
use std::fmt;
use reqwest::Client;
use std::io::Write;
use itertools::{izip, Itertools};
use cryptid::elgamal::{CryptoContext, Ciphertext, CurveElem, PublicKey};
use cryptid::commit::PedersenCtx;
use cryptid::threshold::{Decryption, Threshold};
use common::sign::SignedMessage;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use rayon::prelude::*;
use cryptid::Scalar;
use common::trustee::AcceptedMixRow;

#[derive(Debug)]
enum VerifyError {
    DataMissing,
    UnexpectedResponse,
    Api(Response),
}

impl Display for VerifyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for VerifyError {}

#[tokio::main]
async fn main() -> Result<(), Report> {
    let cfg: PapervoteConfig = confy::load(APP_NAME)?;

    let matches = App::new("Verifiable Vote-by-Mail: Verify")
        .version("0.1")
        .author("Eleanor McMurtry <elmcmurtry1@gmail.com>")
        .about("Verifies the result for the verifiable vote-by-mail protocol.")
        .subcommand(SubCommand::with_name("all")
            .about("Verifies all information, not just for one voter ID"))
        .get_matches();

    if let Some(_) = matches.subcommand_matches("all") {
        if !verify_all(&cfg).await? {
            println!("Global verification failed.");
            return Ok(());
        }
    } else {
        print!("Enter your voter ID: ");
        std::io::stdout().flush()?;

        let mut voter_id_input = String::new();
        std::io::stdin().read_line(&mut voter_id_input)?;
        let voter_id = VoterId::from(voter_id_input.trim().to_string());
        verify_voter(&cfg, voter_id).await?;
    }

    println!("OK.");
    Ok(())
}

async fn get(client: &Client, cfg: &PapervoteConfig, path: &str) -> Result<Response, Report> {
    let response: WrappedResponse = client.get(&format!("{}/{}{}", cfg.api_url, cfg.session_id, path))
        .send().await?
        .json().await?;

    if !response.status {
        Err(VerifyError::Api(response.msg))?
    } else {
        Ok(response.msg)
    }
}

async fn verify_voter(cfg: &PapervoteConfig, voter_id: VoterId) -> Result<(), Report> {
    let client = Client::new();
    if let Response::AcceptedRows(rows) = get(&client, &cfg, "/tally/accepted").await? {
        if rows.into_iter().any(|row| row.voter_id == voter_id) {
            println!("Verification successful.");
        } else {
            println!("Verification failed.");
        }
    } else {
        return Err(VerifyError::UnexpectedResponse)?;
    }

    Ok(())
}

async fn verify_all(cfg: &PapervoteConfig) -> Result<bool, Report> {
    let ctx = CryptoContext::new()?;
    let client = Client::new();
    let commit_ctx = PedersenCtx::new(cfg.session_id.as_bytes());
    let candidates = common::voter::candidates_from_file(&cfg.candidate_file)?;

    // 1. Download trustees and public key
    let mut trustees = voter::get_trustee_info(&cfg, &client).await?;
    let mut pubkey = voter::get_pubkey(&cfg, &mut trustees, &client).await?;

    // 2. Download votes
    let votes = match get(&client, &cfg, "/tally/vote").await? {
        Response::Ciphertexts(votes) => Ok(votes),
        msg => Err(VerifyError::Api(msg)),
    }?;

    // 3. Check 1st mix proofs
    let votes = match get(&client, &cfg, "/tally/vote_mix").await? {
        Response::VoteMixProofs(mut proofs) => {
            if proofs.len() > 0 {
                // For some reason, proofs aren't in order.
                // TODO: Check the DB for ORDER BY?
                proofs.sort_by_key(|proof| proof.index);

                let (_, generators) = PedersenCtx::with_generators(cfg.session_id.as_bytes(), proofs[0].enc_votes.len());
                let mut prev_row = votes;
                for row in proofs {
                    // Check the signature
                    if let Some(info) = trustees.iter()
                        .filter(|trustee| trustee.id == row.signed_by)
                        .next() {
                        // reconstruct the message; yes, this is gross.
                        let msg = SignedMessage {
                            inner: TrusteeMessage::EcVoteMix {
                                mix_index: row.index,
                                enc_votes: row.enc_votes.clone(),
                                enc_voter_ids: row.enc_voter_ids.clone(),
                                enc_as: row.enc_as.clone(),
                                enc_bs: row.enc_bs.clone(),
                                enc_r_as: row.enc_r_as.clone(),
                                enc_r_bs: row.enc_r_bs.clone(),
                                proof: row.proof.clone()
                            },
                            signature: row.signature,
                            sender_id: row.signed_by,
                        };
                        if !msg.verify(&info.pubkey)? {
                            println!("Trustee signature failed: {}", row.signed_by);
                            return Ok(false);
                        }
                    } else {
                        println!("Unknown trustee: {}", row.signed_by);
                        return Ok(false);
                    }
                    // Check the proof and construct the next set
                    let mut next_row = Vec::new();
                    for (vote, id, enc_a, enc_b, enc_r_a, enc_r_b) in izip!(row.enc_votes, row.enc_voter_ids, row.enc_as, row.enc_bs, row.enc_r_as, row.enc_r_bs) {
                        next_row.push(vec![vote, id, enc_a, enc_b, enc_r_a, enc_r_b]);
                    }

                    if !row.proof.verify(&ctx, &commit_ctx, &generators, &prev_row, &next_row, &pubkey) {
                        println!("First shuffle proof: #{} failed.", row.index);
                        return Ok(false);
                    }

                    prev_row = next_row;
                }
                Ok(prev_row)
            } else {
                Ok(Vec::new())
            }
        },
        _ => Err(VerifyError::UnexpectedResponse)
    }?;

    // 4. Check 1st mix decryption proofs
    let vote_dec_shares = match get(&client, &cfg, "/tally/mixed").await? {
        Response::DecryptShares(shares) => Ok(shares),
        msg => Err(VerifyError::Api(msg)),
    }?;

    // Perform decryption using the posted shares
    let mut plaintexts = Vec::new();
    for (vote, shares) in votes.iter().zip(vote_dec_shares) {
        let mut decryptions = vec![
            Decryption::new(cfg.min_trustees, &ctx, &vote[1]),
            Decryption::new(cfg.min_trustees, &ctx, &vote[2]),
            Decryption::new(cfg.min_trustees, &ctx, &vote[3]),
            Decryption::new(cfg.min_trustees, &ctx, &vote[4]),
            Decryption::new(cfg.min_trustees, &ctx, &vote[5])
        ];
        for share_set in shares {
            if let Some(info) = trustees.iter()
                .filter(|trustee| trustee.id == share_set.trustee_id)
                .next() {
                for (dec, share) in decryptions.iter_mut().zip(share_set.shares) {
                    dec.add_share(info.index, &info.pubkey_proof.as_ref().unwrap(), &share);
                }
            } else {
                println!("Unknown trustee: {}", share_set.trustee_id);
                return Ok(false);
            }
        }

        match decryptions.into_iter()
            .map(|dec| dec.finish())
            .collect::<Result<Vec<_>, _>>() {
            Ok(results) => {
                plaintexts.push(results);
            }
            Err(e) => {
                eprintln!("Decryption failed for a vote: {}", e);
                return Ok(false);
            }
        }
    }

    // 5. Check PET proofs
    let (pet_result, validated_voter_ids) = check_pets(&client, &cfg, &mut pubkey, &ctx, &commit_ctx, &trustees, &votes, &mut plaintexts).await?;
    if !pet_result {
        return Ok(false);
    }

    // 6. Check accepted votes
    let mut seen_accepted_votes = HashSet::new();
    let accepted_votes = match get(&client, &cfg, "/tally/accepted").await? {
        Response::AcceptedRows(rows) => Ok(rows.into_iter()
            .map(|row| {
                seen_accepted_votes.insert(row.voter_id);
                vec![row.enc_vote, row.enc_voter_id]
            })
            .collect_vec()),
        msg => Err(VerifyError::Api(msg)),
    }?;

    if seen_accepted_votes != validated_voter_ids.unwrap() {
        println!("Wrong accepted vote set.");
        return Ok(false);
    }

    match get(&client, &cfg, "/tally/accepted/mix").await? {
        Response::AcceptedMixProofs(mut proofs) => {
            if proofs.len() > 0 {
                // For some reason, proofs aren't in order.
                // TODO: Check the DB for ORDER BY?
                proofs.sort_by_key(|proof| proof.index);

                let (_, generators) = PedersenCtx::with_generators(cfg.session_id.as_bytes(), proofs[0].enc_votes.len());
                let mut prev_row = accepted_votes;
                for row in proofs {
                    // Check the signature
                    if let Some(info) = trustees.iter()
                        .filter(|trustee| trustee.id == row.signed_by)
                        .next() {
                        let inner = TrusteeMessage::AcceptedMix {
                            mix_index: row.index,
                            rows: izip!(&row.enc_votes, &row.enc_voter_ids)
                                .map(|(vote, id)| (vote.clone(), id.clone()))
                                .map(|(vote, id)| AcceptedMixRow { vote, id })
                                .collect_vec(),
                            proof: row.proof.clone(),
                        };
                        // reconstruct the message; yes, this is gross.
                        let msg = SignedMessage {
                            inner,
                            signature: row.signature,
                            sender_id: row.signed_by,
                        };
                        if !msg.verify(&info.pubkey)? {
                            println!("Trustee signature failed: {}", row.signed_by);
                            return Ok(false);
                        }
                    } else {
                        println!("Unknown trustee: {}", row.signed_by);
                        return Ok(false);
                    }
                    // Check the proof and construct the next set
                    let mut next_row = Vec::new();
                    for (vote, id) in izip!(row.enc_votes, row.enc_voter_ids) {
                        next_row.push(vec![vote, id]);
                    }

                    if !row.proof.verify(&ctx, &commit_ctx, &generators, &prev_row, &next_row, &pubkey) {
                        println!("Final shuffle proof: #{} failed.", row.index);
                        return Ok(false);
                    }

                    prev_row = next_row;
                }
                Ok(prev_row)
            } else {
                Ok(Vec::new())
            }

        },
        _ => Err(VerifyError::UnexpectedResponse)
    }?;

    // 7. Check accepted decryption proofs
    // Download final set
    let results = match get(&client, &cfg, &format!("/tally/accepted/mix/{}", cfg.trustee_count - 1)).await? {
        Response::AcceptedMixRows(results) => {
            let mut result_map = HashMap::new();
            for (i, row) in results.into_iter().enumerate() {
                result_map.insert(i as i32, row);
            }

            Ok(result_map)
        },
        _ => Err(VerifyError::UnexpectedResponse),
    }?;

    // Download decryption shares
    let decrypt_shares = match get(&client, &cfg, "/tally/accepted/decrypt").await? {
        Response::AcceptedDecryptions(results) => Ok(results),
        _ => Err(VerifyError::UnexpectedResponse),
    }?;

    let mut decryptions = HashMap::new();

    for (trustee, shares) in decrypt_shares {
        if let Some(trustee) = trustees.iter().filter(|t| t.id == trustee).next() {
            for (index, share) in shares {
                println!("Vote {}, trustee {}", index, trustee.index);
                if !share.verify(&trustee.pubkey) {
                    println!("Trustee failed signature in final decryption: {}", trustee.id);
                    return Ok(false);
                }
                let dec = decryptions.entry(index)
                    .or_insert(Decryption::new(cfg.min_trustees, &ctx, &results[&index].vote));
                println!("adding share from {} to vote index {}", trustee.index, index);
                dec.add_share(trustee.index, trustee.pubkey_proof.as_ref().unwrap(), &share.decrypt_share);
            }
        } else {
            println!("Unrecognised trustee: {}", trustee);
            return Ok(false);
        }
    }

    // 8. Check final tally
    let mut votes = decryptions.into_iter().map(|(_, decryption)| {
        assert!(decryption.is_complete());
        let result = decryption.finish().unwrap();
        println!("{:?}", result);

        // Brute-force g to the power of ...
        let value = (0..candidates.len()).permutations(candidates.len())
            .map(|perm| {
                let string_rep: String = perm.into_iter()
                    .map(|c| char::from_digit(c as u32, 36).unwrap())
                    .join("");
                Vote::from_string(&string_rep, &candidates)
                    .map(|vote| vote.encode())
                    .filter(|scalar| ctx.g_to(scalar) == result)
            })
            .filter(|opt| opt.is_some())
            .map(|opt| opt.unwrap())
            .next()?;
        Vote::decode(value, &candidates)
    }).filter(|opt| opt.is_some())
        .map(|opt| opt.unwrap())
        .collect::<Vec<_>>();

    let mut tallied_votes = match get(&client, &cfg, "/tally/final").await? {
        Response::Votes(results) => Ok(results),
        _ => Err(VerifyError::UnexpectedResponse)
    }?;

    votes.sort_by_key(|vote| vote.to_string());
    println!("{:?}", votes);
    tallied_votes.sort_by_key(|vote| vote.to_string());

    let votes_simple = votes.iter().map(|vote| vote.to_string()).collect_vec();
    let tallied_votes_simple = tallied_votes.into_iter().map(|vote| vote.to_string()).collect_vec();

    if tallied_votes_simple != votes_simple {
        println!("Votes did not match.");
        return Ok(false);
    }

    for vote in votes {
        println!("{}", vote.pretty());
    }

    Ok(true)
}

async fn check_pets(
    client: &Client,
    cfg: &PapervoteConfig,
    pubkey: &mut PublicKey,
    ctx: &CryptoContext,
    commit_ctx: &PedersenCtx,
    trustees: &[TrusteeInfo],
    votes: &[Vec<Ciphertext>],
    plaintexts: &mut [Vec<CurveElem>]
) -> Result<(bool, Option<HashSet<VoterId>>), Report> {
    // Decode decryptions
    let mut rows = Vec::new();
    let mut voter_id_counts = HashMap::new();

    for row in plaintexts.into_iter() {
        if let Ok(voter_id) = VoterId::try_from(row[0]) {
            *voter_id_counts.entry(voter_id.clone())
                .or_insert(0usize) += 1;

            let r_b = row.remove(4);
            let b = row.remove(3);
            let r_a = row.remove(2);
            let a = row.remove(1);
            rows.push((voter_id, a, r_a, b, r_b));
        } else {
            eprintln!("Decoding voter ID failed.");
        }
    }

    // Get commitments
    let ec_commits = match get(&client, &cfg, "/cast/commit").await? {
        Response::ResultSet(results) => {
            results.into_iter()
                .map(|msg| {
                    match msg.inner {
                        TrusteeMessage::EcCommit(commit) => Some(commit),
                        _ => None,
                    }
                })
                .collect::<Option<Vec<_>>>()
                .ok_or(VerifyError::UnexpectedResponse)
        },
        _ => Err(VerifyError::UnexpectedResponse)
    }?;

    let mut ec_commit_map = HashMap::new();
    for commit in ec_commits {
        ec_commit_map.entry(commit.voter_id)
            .or_insert(Vec::new())
            .push((commit.enc_mac, commit.enc_vote));
    }

    // Check uniqueness of IDs and EC commitments
    let unique_rows: Vec<_> = rows.into_iter()
        .filter(|(voter_id, _, _, _, _)| {
            let result = voter_id_counts[voter_id] == 1;
            if !result {
                println!("Voter {} did not have a unique entry in the mixed votes, excluding.", voter_id);
            }
            result
        })
        .collect();

    // Get idents
    let idents = match get(&client, &cfg, "/cast/ident").await? {
        Response::Idents(idents) => Ok(idents),
        _ => Err(VerifyError::UnexpectedResponse)
    }?;
    let mut ident_map = HashMap::new();
    for ident in idents {
        ident_map.entry(ident.id)
            .or_insert(Vec::new())
            .push((ident.c_a, ident.c_b));
    }

    // Verify the commitments from the voter and EC to produce a set of votes for PETing
    let mut to_pet: Vec<Option<_>> = Vec::new();
    to_pet.par_extend(unique_rows.into_par_iter()
        .zip(votes)
        .map(|((voter_id, a, b, r_a, r_b), vote)| {
            if let Some(commits) = ident_map.get(&voter_id) {
                if let Some(ec_commits) = ec_commit_map.get(&voter_id) {
                    // Only take the first EC commitment as valid; this is one of many possible policies
                    let (enc_mac, enc_vote) = ec_commits[0].clone();

                    // Check the voter commitment
                    for (c_a, c_b) in commits {
                        if c_a.validate(&commit_ctx, &a.into(), &r_a.into())
                            && c_b.validate(&commit_ctx, &b.into(), &r_b.into()) {
                            // Commitments validated
                            let enc_received_vote = vote[0].clone();

                            // Construct PET ciphertexts
                            let vote_ct = Ciphertext {
                                c1: enc_received_vote.c1 - enc_vote.c1,
                                c2: enc_received_vote.c2 - enc_vote.c2,
                            };

                            let enc_b = pubkey.encrypt(&ctx, &ctx.g_to(&b.into()), &Scalar::zero());
                            let received_mac = enc_vote.scaled(&a.into()).add(&enc_b);
                            let mac_ct = Ciphertext {
                                c1: received_mac.c1 - enc_mac.c1,
                                c2: received_mac.c2 - enc_mac.c2,
                            };

                            return Some((voter_id, vote_ct, mac_ct));
                        }
                    }
                }
            }

            None
        }));

    // Sort results by voter ID
    let mut ciphertext_map = HashMap::new();
    for instance in to_pet {
        if let Some((voter_id, vote_ct, mac_ct)) = instance {
            ciphertext_map.insert(voter_id, (vote_ct, mac_ct));
        }
    }

    // Get PET commitments + openings
    let mut commits = match get(&client, &cfg, "/tally/pet/commit").await? {
        Response::PetCommits(results) => Ok(results),
        _ => Err(VerifyError::UnexpectedResponse),
    }?;
    let mut openings = match get(&client, &cfg, "/tally/pet/opening").await? {
        Response::PetOpenings(results) => Ok(results),
        _ => Err(VerifyError::UnexpectedResponse),
    }?;

    // Check signatures
    for trustee in trustees.iter() {
        if commits.contains_key(&trustee.id) && openings.contains_key(&trustee.id) {
            let commit_rows = &commits[&trustee.id];
            let opening_rows = &openings[&trustee.id];

            for voter_id in commit_rows.keys() {
                if opening_rows.contains_key(voter_id) {
                    let commit = &commit_rows[voter_id];
                    let opening = &opening_rows[voter_id];

                    let mut bytes = Vec::new();
                    bytes.extend_from_slice(voter_id.to_string().as_bytes());
                    bytes.extend_from_slice(commit.1.to_string().as_bytes());
                    bytes.extend_from_slice(commit.2.to_string().as_bytes());

                    if !trustee.pubkey.verify(&bytes, &commit.0)
                        || !opening.verify(&trustee.pubkey, voter_id) {
                        println!("Trustee failed signature: {}", trustee.id);
                        return Ok((false, None));
                    }
                }
            }
        }
    }

    // Reconstruct ciphertexts
    let mut voter_id_validations = HashMap::new();
    let mut combined_vote_cts = HashMap::new();
    let mut combined_mac_cts = HashMap::new();

    for trustee in trustees {
        let mut these_commits = commits.remove(&trustee.id).unwrap();
        let these_openings = openings.remove(&trustee.id).unwrap();

        for (voter_id, opening) in these_openings {
            let (_, vote_commit, mac_commit) = these_commits.remove(&voter_id)
                .ok_or(VerifyError::DataMissing)?;
            if let Some((vote_ct, mac_ct)) = ciphertext_map.get(&voter_id) {
                // Check the commitment openings
                if !vote_commit.validate(
                    &commit_ctx,
                    &opening.vote_opening.ct,
                    (&opening.vote_opening.r1, &opening.vote_opening.r2)) {
                    eprintln!("Voter {} from trustee {}: vote PET commitment opening failed", voter_id, trustee.id);
                    return Ok((false, None));
                }
                if !mac_commit.validate(
                    &commit_ctx,
                    &opening.mac_opening.ct,
                    (&opening.mac_opening.r1, &opening.mac_opening.r2)) {
                    eprintln!("Voter {} from trustee {}: MAC PET commitment opening failed", voter_id, trustee.id);
                    return Ok((false, None));
                }

                // Check the proofs
                if !(opening.vote_proof.verify()
                    && opening.vote_proof.base1 == vote_ct.c1
                    && opening.vote_proof.base2 == vote_ct.c2
                    && opening.vote_proof.result1 == opening.vote_opening.ct.c1
                    && opening.vote_proof.result2 == opening.vote_opening.ct.c2) {
                    eprintln!("Voter {} from trustee {}: vote PET proof failed", voter_id, trustee.id);
                    return Ok((false, None));
                }
                if !(opening.mac_proof.verify()
                    && opening.mac_proof.base1 == mac_ct.c1
                    && opening.mac_proof.base2 == mac_ct.c2
                    && opening.mac_proof.result1 == opening.mac_opening.ct.c1
                    && opening.mac_proof.result2 == opening.mac_opening.ct.c2) {
                    eprintln!("Voter {} from trustee {}: MAC PET proof failed", voter_id, trustee.id);
                    return Ok((false, None));
                }

                *voter_id_validations.entry(voter_id.clone())
                    .or_insert(0usize) += 1;

                // Add in this part of the ciphertexts
                let vote_ct_part = combined_vote_cts.entry(voter_id.clone())
                    .or_insert(Ciphertext::identity());
                let vote_ct_part = vote_ct_part.add(&opening.vote_opening.ct);
                combined_vote_cts.insert(voter_id.clone(), vote_ct_part);

                let mac_ct_part = combined_mac_cts.entry(voter_id.clone())
                    .or_insert(Ciphertext::identity());
                let mac_ct_part = mac_ct_part.add(&opening.mac_opening.ct);
                combined_mac_cts.insert(voter_id.clone(), mac_ct_part);
            } else {
                eprintln!("Voter {} missing from trustee {}", voter_id, trustee.id);
                return Ok((false, None));
            }
        }
    }

    let valid_voters = voter_id_validations.into_iter()
        .filter(|(_, count)| *count >= cfg.min_trustees)
        .map(|(voter_id, _)| voter_id)
        .collect::<HashSet<_>>();

    // Get PET decryptions
    let decryption_msgs = match get(&client, &cfg, "/tally/pet/decrypt").await? {
        Response::PetDecryptions(results) => Ok(results),
        _ => Err(VerifyError::UnexpectedResponse)
    }?;
    let mut decryptions = HashMap::new();
    let mut seen_voter_ids = HashSet::new();

    for trustee in trustees.iter() {
        if decryption_msgs.contains_key(&trustee.id) {
            let msg = &decryption_msgs[&trustee.id];
            for (voter_id, shares) in msg {
                seen_voter_ids.insert(voter_id.clone());
                // Check signature
                if !shares.verify(&trustee.pubkey, voter_id) {
                    println!("Trustee failed signature in PET decryption: {}", trustee.id);
                    return Ok((false, None));
                }
                // Add decryption
                if !decryptions.contains_key(voter_id) {
                    let vote_decrypt = Decryption::new(cfg.min_trustees,
                                                       &ctx,
                                                       &combined_vote_cts[&voter_id]);
                    let mac_decrypt = Decryption::new(cfg.min_trustees,
                                                      &ctx,
                                                      &combined_mac_cts[&voter_id]);
                    decryptions.insert(voter_id.clone(), (vote_decrypt, mac_decrypt));
                }

                let (vote_decrypt, mac_decrypt) = decryptions.get_mut(&voter_id).unwrap();
                vote_decrypt.add_share(trustee.index, trustee.pubkey_proof.as_ref().unwrap(), &shares.vote_share);
                mac_decrypt.add_share(trustee.index, trustee.pubkey_proof.as_ref().unwrap(), &shares.mac_share);
            }
        }
    }

    // Check the right voters were counted
    if seen_voter_ids != valid_voters {
        println!("Incorrect set of VoterIDs were PET'd.");
        return Ok((false, None));
    }

    let mut validated_voter_ids = HashSet::new();
    for (voter_id, (vote_decrypt, mac_decrypt)) in decryptions {
        if let Ok(vote_pet) = vote_decrypt.finish() {
            if let Ok(mac_pet) = mac_decrypt.finish() {
                if vote_pet == CurveElem::identity() && mac_pet == CurveElem::identity() {
                    validated_voter_ids.insert(voter_id);
                }
            } else {
                eprintln!("MAC PET decrypt failed for {}", voter_id);
                return Ok((false, None));
            }
        } else {
            eprintln!("Vote PET decrypt failed for {}", voter_id);
            return Ok((false, None));
        }
    }

    Ok((true, Some(validated_voter_ids)))
}