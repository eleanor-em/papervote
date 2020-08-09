use reqwest::multipart::{Form, Part};
use common::net::{TrusteeMessage, WrappedResponse, Response, TrusteeInfo};
use common::sign::{SignedMessage, SigningKeypair, Signature};
use common::voter::{VoterId, VoterIdent};
use cryptid::elgamal::Ciphertext;
use crate::{TrusteeError, InternalInfo};
use itertools::izip;
use uuid::Uuid;
use cryptid::shuffle::ShuffleProof;
use cryptid::threshold::{ThresholdParty, DecryptShare};
use cryptid::commit::{CtCommitment};
use std::collections::HashMap;
use common::trustee::{EcCommit, SignedDecryptShareSet, SignedPetOpening, SignedPetDecryptShare, AcceptedRow, AcceptedMixRow, SignedDecryptShare};

fn sign(keypair: &SigningKeypair, msg: &TrusteeMessage) -> Result<Signature, TrusteeError> {
    let data = serde_json::to_string(&msg)?.as_bytes().to_vec();
    Ok(keypair.sign(&data))
}

pub async fn post_ec_commit(
    info: &InternalInfo,
    voter_id: VoterId,
    enc_mac: Ciphertext,
    enc_vote: Ciphertext
) -> Result<(), TrusteeError> {
    let inner = TrusteeMessage::EcCommit(EcCommit { voter_id, enc_mac, enc_vote });
    let signature = sign(&info.signing_keypair, &inner)?;

    let msg = SignedMessage {
        inner,
        signature,
        sender_id: info.id.clone(),
    };

    // Post to WBB
    let response: WrappedResponse = info.client.post(&format!("{}/{}/cast/commit", &info.api_base_addr, &info.session_id))
        .json(&msg).send().await?
        .json().await?;

    if !response.status {
        Err(TrusteeError::FailedResponse(response.msg))
    } else {
        Ok(())
    }
}

pub async fn post_shuffle(
    info: &InternalInfo,
    enc_votes: Vec<Ciphertext>,
    enc_voter_ids: Vec<Ciphertext>,
    enc_as: Vec<Ciphertext>,
    enc_bs: Vec<Ciphertext>,
    enc_r_as: Vec<Ciphertext>,
    enc_r_bs: Vec<Ciphertext>,
    proof: ShuffleProof
) -> Result<(), TrusteeError> {
    let inner = TrusteeMessage::EcVoteMix {
        mix_index: info.index as i16,
        enc_votes,
        enc_voter_ids,
        enc_as,
        enc_bs,
        enc_r_as,
        enc_r_bs,
        proof,
    };
    let signature = sign(&info.signing_keypair, &inner)?;

    let msg = SignedMessage {
        inner,
        signature,
        sender_id: info.id.clone()
    };

    // Construct multipart form
    let bytes = serde_json::to_string(&msg)?;
    let bytes = bytes.as_bytes().to_vec();
    let form = Form::new().part("msg", Part::bytes(bytes.clone()));

    let response: WrappedResponse = info.client.post(&format!("{}/{}/tally/vote_mix", &info.api_base_addr, &info.session_id))
        .multipart(form)
        .send().await?
        .json().await?;

    if !response.status {
        Err(TrusteeError::FailedResponse(response.msg))
    } else {
        Ok(())
    }
}

pub async fn post_decrypt_shares(
    info: &InternalInfo,
    signatures: Vec<Signature>,
    shares: Vec<Vec<DecryptShare>>
) -> Result<(), TrusteeError> {
    let inner = TrusteeMessage::EcVoteDecrypt {
        signatures,
        shares,
    };
    let signature = sign(&info.signing_keypair, &inner)?;

    let msg = SignedMessage {
        inner,
        signature,
        sender_id: info.id.clone()
    };

    // Construct multipart form
    let bytes = serde_json::to_string(&msg)?;
    let bytes = bytes.as_bytes().to_vec();
    let form = Form::new().part("msg", Part::bytes(bytes.clone()));

    let response: WrappedResponse = info.client.post(&format!("{}/{}/tally/mixed", &info.api_base_addr, &info.session_id))
        .multipart(form)
        .send().await?
        .json().await?;

    if !response.status {
        Err(TrusteeError::FailedResponse(response.msg))
    } else {
        Ok(())
    }
}

pub async fn post_pet_commits(
    info: &InternalInfo,
    voter_ids: Vec<VoterId>,
    vote_commits: Vec<CtCommitment>,
    mac_commits: Vec<CtCommitment>,
    signatures: Vec<Signature>
) -> Result<(), TrusteeError> {
    let inner = TrusteeMessage::EcPetCommit {
        voter_ids,
        vote_commits,
        mac_commits,
        signatures,
    };

    let signature = sign(&info.signing_keypair, &inner)?;

    let msg = SignedMessage {
        inner,
        signature,
        sender_id: info.id.clone()
    };

    // Construct multipart form
    let bytes = serde_json::to_string(&msg)?;
    let bytes = bytes.as_bytes().to_vec();
    let form = Form::new().part("msg", Part::bytes(bytes.clone()));

    let response: WrappedResponse = info.client.post(&format!("{}/{}/tally/pet/commit", &info.api_base_addr, &info.session_id))
        .multipart(form)
        .send().await?
        .json().await?;

    if !response.status {
        Err(TrusteeError::FailedResponse(response.msg))
    } else {
        Ok(())
    }
}

pub async fn post_pet_openings(
    info: &InternalInfo,
    voter_ids: Vec<VoterId>,
    openings: Vec<SignedPetOpening>
) -> Result<(), TrusteeError> {
    let inner = TrusteeMessage::EcPetOpening {
        voter_ids,
        openings,
    };

    let signature = sign(&info.signing_keypair, &inner)?;

    let msg = SignedMessage {
        inner,
        signature,
        sender_id: info.id.clone()
    };

    // Construct multipart form
    let bytes = serde_json::to_string(&msg)?;
    let bytes = bytes.as_bytes().to_vec();
    let form = Form::new().part("msg", Part::bytes(bytes.clone()));

    let response: WrappedResponse = info.client.post(&format!("{}/{}/tally/pet/opening", &info.api_base_addr, &info.session_id))
        .multipart(form)
        .send().await?
        .json().await?;

    if !response.status {
        Err(TrusteeError::FailedResponse(response.msg))
    } else {
        Ok(())
    }
}

pub async fn post_pet_decryptions(
    info: &InternalInfo,
    voter_ids: Vec<VoterId>,
    shares: Vec<SignedPetDecryptShare>
) -> Result<(), TrusteeError> {
    let inner = TrusteeMessage::EcPetDecrypt {
        voter_ids,
        shares,
    };

    let signature = sign(&info.signing_keypair, &inner)?;

    let msg = SignedMessage {
        inner,
        signature,
        sender_id: info.id.clone()
    };

    // Construct multipart form
    let bytes = serde_json::to_string(&msg)?;
    let bytes = bytes.as_bytes().to_vec();
    let form = Form::new().part("msg", Part::bytes(bytes.clone()));

    let response: WrappedResponse = info.client.post(&format!("{}/{}/tally/pet/decrypt", &info.api_base_addr, &info.session_id))
        .multipart(form)
        .send().await?
        .json().await?;

    if !response.status {
        Err(TrusteeError::FailedResponse(response.msg))
    } else {
        Ok(())
    }
}

pub async fn post_accepted(
    info: &InternalInfo,
    voter_ids: Vec<VoterId>,
    enc_votes: Vec<Ciphertext>
) -> Result<(), TrusteeError> {
    let mut enc_proofs = Vec::new();
    let mut enc_ids = Vec::new();

    for voter_id in voter_ids.iter() {
        let r = info.ctx.random_scalar();
        let enc_id = info.pubkey.encrypt(&info.ctx, &voter_id.try_as_curve_elem()
            .ok_or(TrusteeError::Encode)?, &r);

        enc_proofs.push(r);
        enc_ids.push(enc_id);
    }

    let mut rows = Vec::new();
    for (voter_id, enc_voter_id, enc_proof, enc_vote) in izip!(voter_ids, enc_ids, enc_proofs, enc_votes) {
        rows.push(AcceptedRow {
            voter_id, enc_voter_id, enc_proof, enc_vote
        });
    }

    let inner = TrusteeMessage::Accepted { rows };
    let signature = sign(&info.signing_keypair, &inner)?;

    let msg = SignedMessage {
        inner,
        signature,
        sender_id: info.id.clone()
    };

    // Construct multipart form
    let bytes = serde_json::to_string(&msg)?;
    let bytes = bytes.as_bytes().to_vec();
    let form = Form::new().part("msg", Part::bytes(bytes.clone()));

    let response: WrappedResponse = info.client.post(&format!("{}/{}/tally/accepted", &info.api_base_addr, &info.session_id))
        .multipart(form)
        .send().await?
        .json().await?;

    if !response.status {
        Err(TrusteeError::FailedResponse(response.msg))
    } else {
        Ok(())
    }
}

pub async fn post_accepted_shuffle(
    info: &InternalInfo,
    enc_votes: Vec<Ciphertext>,
    enc_voter_ids: Vec<Ciphertext>,
    proof: ShuffleProof
) -> Result<(), TrusteeError> {
    let mut rows = Vec::new();
    for (vote, id) in enc_votes.into_iter().zip(enc_voter_ids) {
        rows.push(AcceptedMixRow {
            vote, id
        });
    }

    let inner = TrusteeMessage::AcceptedMix {
        mix_index: info.index as i16,
        rows,
        proof,
    };
    let signature = sign(&info.signing_keypair, &inner)?;

    let msg = SignedMessage {
        inner,
        signature,
        sender_id: info.id.clone()
    };

    // Construct multipart form
    let bytes = serde_json::to_string(&msg)?;
    let bytes = bytes.as_bytes().to_vec();
    let form = Form::new().part("msg", Part::bytes(bytes.clone()));

    let response: WrappedResponse = info.client.post(&format!("{}/{}/tally/accepted/mix", &info.api_base_addr, &info.session_id))
        .multipart(form)
        .send().await?
        .json().await?;

    if !response.status {
        Err(TrusteeError::FailedResponse(response.msg))
    } else {
        Ok(())
    }
}

pub async fn post_accepted_decryptions(
    info: &InternalInfo,
    shares: Vec<SignedDecryptShare>
) -> Result<(), TrusteeError> {
    let inner = TrusteeMessage::AcceptedDecrypt {
        shares,
    };

    let signature = sign(&info.signing_keypair, &inner)?;

    let msg = SignedMessage {
        inner,
        signature,
        sender_id: info.id.clone()
    };

    // Construct multipart form
    let bytes = serde_json::to_string(&msg)?;
    let bytes = bytes.as_bytes().to_vec();
    let form = Form::new().part("msg", Part::bytes(bytes.clone()));

    let response: WrappedResponse = info.client.post(&format!("{}/{}/tally/accepted/decrypt", &info.api_base_addr, &info.session_id))
        .multipart(form)
        .send().await?
        .json().await?;

    if !response.status {
        Err(TrusteeError::FailedResponse(response.msg))
    } else {
        Ok(())
    }
}

pub async fn get_votes(
    info: &InternalInfo,
    party: &ThresholdParty
) -> Result<Vec<Vec<Ciphertext>>, TrusteeError> {
    // Download votes
    let response: WrappedResponse = info.client.get(&format!("{}/{}/tally/vote_mix/{}",
                                                                  &info.api_base_addr,
                                                                  &info.session_id,
                                                                  party.trustee_count()))
        .send().await?
        .json().await?;

    if !response.status {
        return Err(TrusteeError::FailedResponse(response.msg));
    }

    let votes = match response.msg {
        Response::Ciphertexts(cts) => cts,
        _ => {
            return Err(TrusteeError::InvalidResponse);
        }
    };

    Ok(votes)
}

pub async fn get_idents(info: &InternalInfo) -> Result<Vec<VoterIdent>, TrusteeError> {
    // Download decryption shares
    let response: WrappedResponse = info.client.get(&format!("{}/{}/cast/ident",
                                                                  &info.api_base_addr,
                                                                  &info.session_id))
        .send().await?
        .json().await?;

    if !response.status {
        return Err(TrusteeError::FailedResponse(response.msg));
    }

    match response.msg {
        Response::Idents(idents) => Ok(idents),
        _ => Err(TrusteeError::InvalidResponse)
    }
}

pub async fn get_ec_commitments(info: &InternalInfo) -> Result<Vec<EcCommit>, TrusteeError> {
    // Download decryption shares
    let response: WrappedResponse = info.client.get(&format!("{}/{}/cast/commit",
                                                                  &info.api_base_addr,
                                                                  &info.session_id))
        .send().await?
        .json().await?;

    if !response.status {
        return Err(TrusteeError::FailedResponse(response.msg));
    }

    match response.msg {
        Response::ResultSet(results) => {
            results.into_iter()
                .map(|msg| {
                    match msg.inner {
                        TrusteeMessage::EcCommit(commit) => Some(commit),
                        _ => None,
                    }
                }).collect::<Option<_>>()
                .ok_or(TrusteeError::InvalidResponse)
        },
        _ => {
            Err(TrusteeError::InvalidResponse)
        }
    }
}

pub async fn get_decrypt_shares(trustee_info: &HashMap<Uuid, TrusteeInfo>, info: &InternalInfo) -> Result<Vec<Vec<SignedDecryptShareSet>>, TrusteeError> {
    let response: WrappedResponse = info.client.get(&format!("{}/{}/tally/mixed",
                                                                  &info.api_base_addr,
                                                                  &info.session_id))
        .send().await?
        .json().await?;

    if !response.status {
        return Err(TrusteeError::FailedResponse(response.msg));
    }

    let decrypt_shares = match response.msg {
        Response::DecryptShares(shares) => shares,
        _ => {
            return Err(TrusteeError::InvalidResponse);
        }
    };

    // Check signatures
    for share_row in decrypt_shares.iter() {
        for share_set in share_row.iter() {
            if !share_set.verify(&trustee_info[&share_set.trustee_id].pubkey) {
                return Err(TrusteeError::InvalidSignature);
            }
        }
    }

    Ok(decrypt_shares)
}

pub async fn count_pet_commits(info: &InternalInfo) -> Result<i64, TrusteeError> {
    let response: WrappedResponse = info.client.get(&format!("{}/{}/tally/pet/commit/count",
                                                             &info.api_base_addr,
                                                             &info.session_id))
        .send().await?
        .json().await?;

    if !response.status {
        return Err(TrusteeError::FailedResponse(response.msg));
    }

    let result = match response.msg {
        Response::Count(result) => result,
        _ => {
            return Err(TrusteeError::InvalidResponse);
        }
    };

    Ok(result)
}

// Returns a map from trustee IDs to a map from voter IDs to pairs (vote_commit, mac_commit).
pub async fn get_pet_commits(trustee_info: &HashMap<Uuid, TrusteeInfo>,
                                info: &InternalInfo
) -> Result<HashMap<Uuid, HashMap<VoterId, (CtCommitment, CtCommitment)>>, TrusteeError> {
    let response: WrappedResponse = info.client.get(&format!("{}/{}/tally/pet/commit",
                                                             &info.api_base_addr,
                                                             &info.session_id))
        .send().await?
        .json().await?;

    if !response.status {
        return Err(TrusteeError::FailedResponse(response.msg));
    }

    let mut commits = match response.msg {
        Response::PetCommits(results) => results,
        _ => {
            return Err(TrusteeError::InvalidResponse);
        }
    };

    let mut result = HashMap::new();

    // Check signatures
    for trustee in trustee_info.keys() {
        let pubkey = &trustee_info[trustee].pubkey;
        let rows = commits.remove(trustee).unwrap();

        for (voter_id, (signature, vote_commit, mac_commit)) in rows.into_iter() {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(voter_id.to_string().as_bytes());
            bytes.extend_from_slice(vote_commit.to_string().as_bytes());
            bytes.extend_from_slice(mac_commit.to_string().as_bytes());

            if !pubkey.verify(&bytes, &signature) {
                return Err(TrusteeError::InvalidSignature);
            } else {
                result.entry(*trustee)
                    .or_insert(HashMap::new())
                    .entry(voter_id)
                    .or_insert((vote_commit, mac_commit));
            }
        }
    }

    Ok(result)
}

pub async fn get_pet_openings(trustee_info: &HashMap<Uuid, TrusteeInfo>,
                                 info: &InternalInfo
) -> Result<HashMap<Uuid, HashMap<VoterId, SignedPetOpening>>, TrusteeError> {
    let response: WrappedResponse = info.client.get(&format!("{}/{}/tally/pet/opening",
                                                             &info.api_base_addr,
                                                             &info.session_id))
        .send().await?
        .json().await?;

    if !response.status {
        return Err(TrusteeError::FailedResponse(response.msg));
    }

    let mut commits = match response.msg {
        Response::PetOpenings(results) => results,
        _ => {
            return Err(TrusteeError::InvalidResponse);
        }
    };

    let mut result = HashMap::new();

    // Check signatures
    for trustee in trustee_info.keys() {
        let pubkey = &trustee_info[trustee].pubkey;
        let rows = commits.remove(trustee).unwrap();

        for (voter_id, opening) in rows {
            if !opening.verify(pubkey, &voter_id) {
                return Err(TrusteeError::InvalidSignature);
            } else {
                result.entry(*trustee)
                    .or_insert(HashMap::new())
                    .entry(voter_id)
                    .or_insert(opening);
            }
        }
    }

    Ok(result)
}

pub async fn get_pet_decryptions(trustee_info: &HashMap<Uuid, TrusteeInfo>,
                                 info: &InternalInfo
) -> Result<HashMap<Uuid, HashMap<VoterId, SignedPetDecryptShare>>, TrusteeError> {
    let response: WrappedResponse = info.client.get(&format!("{}/{}/tally/pet/decrypt",
                                                             &info.api_base_addr,
                                                             &info.session_id))
        .send().await?
        .json().await?;

    if !response.status {
        return Err(TrusteeError::FailedResponse(response.msg));
    }

    let mut shares = match response.msg {
        Response::PetDecryptions(results) => results,
        _ => {
            return Err(TrusteeError::InvalidResponse);
        }
    };

    let mut result = HashMap::new();

    // Check signatures
    for trustee in trustee_info.keys() {
        let pubkey = &trustee_info[trustee].pubkey;
        let rows = shares.remove(trustee).unwrap();

        for (voter_id, share) in rows {
            if !share.verify(pubkey, &voter_id) {
                return Err(TrusteeError::InvalidSignature);
            } else {
                result.entry(*trustee)
                    .or_insert(HashMap::new())
                    .entry(voter_id)
                    .or_insert(share);
            }
        }
    }

    Ok(result)
}

pub async fn get_final_accepted_mix(
    info: &InternalInfo,
    trustee_count: usize
) -> Result<HashMap<i32, AcceptedMixRow>, TrusteeError> {
    let response: WrappedResponse = info.client.get(&format!("{}/{}/tally/accepted/mix/{}", &info.api_base_addr, &info.session_id, trustee_count - 1))
        .send().await?
        .json().await?;

    if !response.status {
        return Err(TrusteeError::FailedResponse(response.msg));
    }

    let results = match response.msg {
        Response::AcceptedMixRows(results) => results,
        _ => {
            return Err(TrusteeError::InvalidResponse);
        }
    };

    let mut result_map = HashMap::new();
    for (i, row) in results.into_iter().enumerate() {
        result_map.insert(i as i32, row);
    }

    Ok(result_map)
}

pub async fn get_accepted_decryptions(trustee_info: &HashMap<Uuid, TrusteeInfo>,
                                      info: &InternalInfo
) -> Result<HashMap<Uuid, HashMap<i32, SignedDecryptShare>>, TrusteeError> {
    let response: WrappedResponse = info.client.get(&format!("{}/{}/tally/accepted/decrypt",
                                                             &info.api_base_addr,
                                                             &info.session_id))
        .send().await?
        .json().await?;

    if !response.status {
        return Err(TrusteeError::FailedResponse(response.msg));
    }

    let mut shares = match response.msg {
        Response::AcceptedDecryptions(results) => results,
        _ => {
            return Err(TrusteeError::InvalidResponse);
        }
    };

    let mut result = HashMap::new();

    // Check signatures
    for trustee in trustee_info.keys() {
        let pubkey = &trustee_info[trustee].pubkey;
        let rows = shares.remove(trustee).unwrap();

        for (index, share) in rows {
            if !share.verify(pubkey) {
                return Err(TrusteeError::InvalidSignature);
            } else {
                result.entry(*trustee)
                    .or_insert(HashMap::new())
                    .entry(index)
                    .or_insert(share);
            }
        }
    }

    Ok(result)
}
