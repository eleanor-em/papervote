use eyre::Report;
use common::voter::VoterId;
use common::config::PapervoteConfig;
use common::APP_NAME;
use common::net::{Response, WrappedResponse, TrusteeMessage};
use clap::{App, SubCommand};
use std::fmt::Display;
use serde::export::Formatter;
use std::fmt;
use reqwest::Client;
use std::io::Write;
use itertools::izip;
use cryptid::elgamal::CryptoContext;
use cryptid::commit::PedersenCtx;
use cryptid::threshold::{Decryption, Threshold};
use common::sign::SignedMessage;

#[derive(Debug)]
enum VerifyError {
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

    // 1. Download trustees and public key
    let mut trustees = voter::get_trustee_info(&cfg, &client).await?;
    let pubkey = voter::get_pubkey(&cfg, &mut trustees, &client).await?;

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

                let (commit_ctx, generators) = PedersenCtx::with_generators(cfg.session_id.as_bytes(), proofs[0].enc_votes.len());
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

    // TODO: Check PETs, check inclusion of votes in accepted list, check accepted mix,
    //       check accepted decryptions.

    Ok(true)
}
