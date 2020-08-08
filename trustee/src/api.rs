use reqwest::multipart::{Form, Part};
use common::net::{TrusteeMessage, WrappedResponse, Response};
use common::sign::{SignedMessage, SigningKeypair};
use common::vote::VoterId;
use cryptid::elgamal::Ciphertext;
use crate::{TrusteeError, InternalInfo};
use uuid::Uuid;
use cryptid::shuffle::ShuffleProof;
use cryptid::threshold::{ThresholdParty, DecryptShare};
use cryptid::commit::Commitment;

fn sign(keypair: &SigningKeypair, msg: &TrusteeMessage) -> Result<Vec<u8>, TrusteeError> {
    let data = serde_json::to_string(&msg)?.as_bytes().to_vec();
    Ok(keypair.sign(&data).as_ref().to_vec())
}

pub async fn post_ec_commit(
    info: &InternalInfo,
    voter_id: VoterId,
    enc_mac: Ciphertext,
    enc_vote: Ciphertext
) -> Result<(), TrusteeError> {
    let inner = TrusteeMessage::EcCommit { voter_id, enc_mac, enc_vote };
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
    signatures: Vec<Vec<u8>>,
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
    vote_commits: Vec<(Commitment, Commitment)>,
    mac_commits: Vec<(Commitment, Commitment)>,
    signatures: Vec<Vec<u8>>
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

pub async fn get_idents(info: &InternalInfo) -> Result<Vec<(VoterId, Commitment, Commitment)>, TrusteeError> {
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
        _ => {
            Err(TrusteeError::InvalidResponse)
        }
    }
}

pub async fn get_ec_commitments(info: &InternalInfo) -> Result<Vec<(VoterId, Ciphertext, Ciphertext)>, TrusteeError> {
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
                    if let TrusteeMessage::EcCommit { voter_id, enc_mac, enc_vote } = msg.inner {
                        Some((voter_id, enc_mac, enc_vote))
                    } else {
                        None
                    }
                }).collect::<Option<_>>()
                .ok_or(TrusteeError::InvalidResponse)
        },
        _ => {
            Err(TrusteeError::InvalidResponse)
        }
    }
}

pub async fn get_decrypt_shares(info: &InternalInfo) -> Result<Vec<Vec<(Uuid, Vec<u8>, Vec<DecryptShare>)>>, TrusteeError> {
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

    Ok(decrypt_shares)
}