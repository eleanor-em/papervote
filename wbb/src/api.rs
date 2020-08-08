use std::str::FromStr;
use std::sync::Arc;

use futures::{executor, TryFutureExt};
use rocket::{Data, State};
use rocket_contrib::json::Json;
use rocket::http::ContentType;
use rocket_multipart_form_data::{MultipartFormDataOptions, MultipartFormData, MultipartFormDataField};
use uuid::Uuid;

use common::sign::SignedMessage;
use crate::db::{DbClient, DbError};
use common::net::{Response, WrappedResponse, TrusteeMessage, NewSessionRequest};
use common::voter::VoterMessage;

pub struct Api {
    db: Arc<DbClient>,
}

impl Api {
    pub async fn new() -> Result<Self, DbError> {
        let db = Arc::new(DbClient::new().await?);

        Ok(Self {
            db,
        })
    }

    pub fn start(self) {
        rocket::ignite().mount("/", rocket::routes![
                new_session,
                register_trustee,
                get_trustees,
                post_commitment,
                get_commitments,
                sign_pubkey,
                get_pubkey_sigs,
                post_ident,
                post_ec_commit,
                find_ec_commit,
                post_ec_vote,
                post_ec_vote_mix,
                post_ec_vote_decrypt,
                post_pet_commits,
                post_pet_openings,
                post_pet_decryptions,
                get_ec_votes,
                get_ec_mix_votes,
                get_ec_vote_decrypt,
                get_idents,
                get_ec_commits,
                get_pet_commit_count,
                get_pet_commits,
                get_pet_openings,
                get_pet_decryptions,
            ])
            .manage(self)
            .launch();
    }
}

fn failure(msg: Response) -> Json<WrappedResponse> {
    Json(WrappedResponse {
        status: false, msg
    })
}

fn success(msg: Response) -> Json<WrappedResponse> {
    Json(WrappedResponse {
        status: true, msg
    })
}

// Below constructions are a bit clunky. We want to early-exit with a prepared error response if
// something goes wrong, but we can't do that directly because Rocket can't return results, so we
// use an inner function and a weird Either<A, A> type.
type EitherResponse = Result<Json<WrappedResponse>, Json<WrappedResponse>>;

fn respond(res: EitherResponse) -> Json<WrappedResponse> {
    match res {
        Ok(res) => res,
        Err(res) => res
    }
}

// Setup queries

#[rocket::post("/api/<session>/trustee/register", format = "json", data = "<msg>")]
fn register_trustee(state: State<'_, Api>, session: String, msg: Json<SignedMessage>) -> Json<WrappedResponse> {
    respond(register_trustee_inner(state, session, msg))
}
fn register_trustee_inner(state: State<'_, Api>, session: String, msg: Json<SignedMessage>) -> EitherResponse {
    let session = Uuid::from_str(&session).map_err(|_| failure(Response::InvalidSession))?;
    let info = match &msg.inner {
        TrusteeMessage::Info { info } => Ok(info),
        _ => Err(failure(Response::InvalidRequest))
    }?;

    let db = state.db.clone();

    // Find the number of trustees we're supposed to have
    let trustee_count = executor::block_on(db.get_trustee_count(&session).map_err(|_| failure(Response::InvalidSession)))?;
    // Find the number of trustees we do have
    let trustees = executor::block_on(db.count_trustees(&session).map_err(|_| failure(Response::InvalidSession)))?;

    // Only insert this trustee if we need more
    if trustees < trustee_count {
        executor::block_on(db.insert_trustee(&session, &info.id, &info.pubkey, info.index, &info.address, &msg.signature))
            .map_err(|e| {
                eprintln!("error registering trustee: {}", e);
                failure(Response::InvalidData)
            })?;
        Ok(success(Response::Ok))
    } else {
        Err(failure(Response::InvalidRequest))
    }
}

#[rocket::post("/api/<session>/new", format = "json", data = "<req>")]
fn new_session(state: State<'_, Api>, session: String, req: Json<NewSessionRequest>) -> Json<WrappedResponse> {
    respond(new_session_inner(state, session, req))
}
fn new_session_inner(state: State<'_, Api>, session: String, req: Json<NewSessionRequest>) -> EitherResponse {
    let session = Uuid::from_str(&session).map_err(|_| failure(Response::InvalidSession))?;
    Ok(match executor::block_on(state.db.clone().insert_session(&session, req.min_trustees, req.trustee_count)) {
        Ok(_) =>  success(Response::Ok),
        Err(_) => failure(Response::SessionExists)
    })
}

#[rocket::get("/api/<session>/trustee/all")]
fn get_trustees(state: State<'_, Api>, session: String) -> Json<WrappedResponse> {
    respond(get_trustees_inner(state, session))
}
fn get_trustees_inner(state: State<'_, Api>, session: String) -> EitherResponse {
    let session = Uuid::from_str(&session).map_err(|_| failure(Response::InvalidSession))?;
    let (trustee_count, trustee_info) = {
        let db = state.db.clone();
        let trustee_count = executor::block_on(db.get_trustee_count(&session).map_err(|_| failure(Response::InvalidSession)))?;
        let trustee_info = executor::block_on(db.get_all_trustee_info(&session).map_err(|_| failure(Response::MiscError)))?;
        (trustee_count, trustee_info)
    };

    if trustee_info.len() == trustee_count {
        Ok(success(Response::ResultSet(trustee_info)))
    } else {
        Err(failure(Response::NotReady))
    }
}

#[rocket::post("/api/<session>/keygen/commitment", format = "json", data = "<msg>")]
fn post_commitment(state: State<'_, Api>, session: String, msg: Json<SignedMessage>) -> Json<WrappedResponse> {
    respond(post_commitment_inner(state, session, msg))
}
fn post_commitment_inner(state: State<'_, Api>, session: String, msg: Json<SignedMessage>) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;
    let commitment = match &msg.inner {
        TrusteeMessage::KeygenCommit { commitment } => Ok(commitment),
        _ => Err(failure(Response::InvalidRequest))
    }?;

    let db = state.db.clone();
    let info = executor::block_on(db.get_one_trustee_info(&session, &msg.sender_id)
        .map_err(|_| failure(Response::TrusteeMissing)))?;
    // Check signature
    match msg.verify(&info.pubkey) {
        Ok(true) => {
            // Add commitment
            executor::block_on(db.insert_commitment(&session, &info.id, &commitment, &msg.signature))
                .map_err(|e| match e {
                    DbError::InsertAlreadyExists => failure(Response::FailedInsertion),
                    _ => {
                        eprintln!("Error: {}", e);
                        failure(Response::MiscError)
                    }
                })?;
            Ok(success(Response::Ok))
        }
        Ok(false) => {
            // Signature failed verification
            Err(failure(Response::InvalidSignature))
        }
        Err(e) => {
            // Something weird happened
            eprintln!("Error: {}", e);
            Err(failure(Response::MiscError))
        }
    }
}

#[rocket::get("/api/<session>/keygen/commitment/all")]
fn get_commitments(state: State<'_, Api>, session: String) -> Json<WrappedResponse> {
    respond(get_commitments_inner(state, session))
}
fn get_commitments_inner(state: State<'_, Api>, session: String) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;
    let db = state.db.clone();
    let trustee_count = executor::block_on(db.get_trustee_count(&session).map_err(|_| failure(Response::InvalidSession)))?;
    let commitments = executor::block_on(db.get_all_commitments(&session))
        .map_err(|e| {
            eprintln!("Error: {}", e);
            failure(Response::MiscError)
        })?;
    if commitments.len() == trustee_count {
        Ok(success(Response::ResultSet(commitments)))
    } else {
        Err(failure(Response::NotReady))
    }
}

#[rocket::post("/api/<session>/keygen/sign", format = "json",  data = "<msg>")]
fn sign_pubkey(state: State<'_, Api>, session: String, msg: Json<SignedMessage>) -> Json<WrappedResponse> {
    respond(sign_pubkey_inner(state, session, msg))
}
fn sign_pubkey_inner(state: State<'_, Api>, session: String, msg: Json<SignedMessage>) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;

    let (pubkey, pubkey_proof) = match &msg.inner {
        TrusteeMessage::KeygenSign { pubkey, pubkey_proof } => Ok((pubkey, pubkey_proof)),
        _ => Err(failure(Response::InvalidRequest))
    }?;

    executor::block_on(state.db.clone().insert_pubkey_sig(&session, &msg.sender_id, pubkey, pubkey_proof, &msg.signature))
        .map_err(|e| {
            eprintln!("Error: {}", e);
            failure(Response::MiscError)
        })?;
    Ok(success(Response::Ok))
}

#[rocket::get("/api/<session>/keygen/sign/all")]
fn get_pubkey_sigs(state: State<'_, Api>, session: String) -> Json<WrappedResponse> {
    respond(get_pubkey_sigs_inner(state, session))
}
fn get_pubkey_sigs_inner(state: State<'_, Api>, session: String) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;
    let results = executor::block_on(state.db.clone().get_all_pubkey_sigs(&session))
        .map_err(|e| {
            eprintln!("Error: {}", e);
            failure(Response::MiscError)
        })?;
    Ok(success(Response::ResultSet(results)))
}

// The protocol itself

#[rocket::post("/api/<session>/cast/ident", format = "json", data = "<msg>")]
fn post_ident(state: State<'_, Api>, session: String, msg: Json<VoterMessage>) -> Json<WrappedResponse> {
    respond(post_ident_inner(state, session, msg))
}
fn post_ident_inner(state: State<'_, Api>, session: String, msg: Json<VoterMessage>) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;

    let ident = match msg.into_inner() {
        VoterMessage::InitialCommit(ident) => Ok(ident),
        _ => Err(failure(Response::InvalidRequest))
    }?;

    Ok(executor::block_on(state.db.clone().insert_ident(&session, ident))
        .map(|_| success(Response::Ok))
        .map_err(|_| failure(Response::TrusteeMissing))?)
}

#[rocket::post("/api/<session>/cast/commit", format = "json", data = "<msg>")]
fn post_ec_commit(state: State<'_, Api>, session: String, msg: Json<SignedMessage>) -> Json<WrappedResponse> {
    respond(post_ec_commit_inner(state, session, msg))
}
fn post_ec_commit_inner(state: State<'_, Api>, session: String, msg: Json<SignedMessage>) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;

    let commit = match &msg.inner {
        TrusteeMessage::EcCommit(commit) => Ok(commit),
        _ => Err(failure(Response::InvalidRequest))
    }?;

    // Verify the signature to ensure this was sent by an EC rep
    let db = state.db.clone();
    let trustee = executor::block_on(db.get_one_trustee_info(&session, &msg.sender_id))
        .map_err(|_| failure(Response::InvalidSignature))?;

    if !msg.verify(&trustee.pubkey).map_err(|_| failure(Response::MiscError))? {
        return Err(failure(Response::InvalidSignature));
    }

    executor::block_on(db.insert_ec_commit(&session, &msg.sender_id, commit, &msg.signature))
        .map_err(|_| failure(Response::FailedInsertion))?;

    Ok(success(Response::Ok))
}

#[rocket::get("/api/<session>/cast/commit/<voter_id>", format = "json")]
fn find_ec_commit(state: State<'_, Api>, session: String, voter_id: String) -> Json<WrappedResponse> {
    respond(find_ec_commit_inner(state, session, voter_id))
}
fn find_ec_commit_inner(state: State<'_, Api>, session: String, voter_id: String) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;

    let result = executor::block_on(state.db.clone().find_ec_commit(&session, voter_id.clone()))
        .map_err(|_| failure(Response::MiscError))?;

    Ok(success(Response::Outcome(result)))
}

#[rocket::post("/api/<session>/tally/vote", format = "json", data = "<msg>")]
fn post_ec_vote(state: State<'_, Api>, session: String, msg: Json<SignedMessage>) -> Json<WrappedResponse> {
    respond(post_ec_vote_inner(state, session, msg))
}
fn post_ec_vote_inner(state: State<'_, Api>, session: String, msg: Json<SignedMessage>) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;

    let (vote, enc_vote, prf_enc_vote, enc_id, enc_a, enc_b, enc_r_a, enc_r_b) = match &msg.inner {
        TrusteeMessage::EcVote {
            vote, enc_vote, prf_enc_vote, enc_id, enc_a, enc_b, enc_r_a, enc_r_b
        } => {
            Ok((vote, enc_vote, prf_enc_vote, enc_id, enc_a, enc_b, enc_r_a, enc_r_b))
        },
        _ => Err(failure(Response::InvalidRequest))
    }?;

    let db = state.db.clone();

    // Verify the signature to ensure this was sent by an EC rep
    let trustee = executor::block_on(db.get_one_trustee_info(&session, &msg.sender_id))
        .map_err(|_| failure(Response::InvalidSignature))?;
    if !msg.verify(&trustee.pubkey).map_err(|_| failure(Response::MiscError))? {
        return Err(failure(Response::InvalidSignature));
    }

    executor::block_on(db.insert_ec_vote(&session, vote.clone(), enc_vote, prf_enc_vote, enc_id, enc_a, enc_b, enc_r_a, enc_r_b, &msg.sender_id, &msg.signature))
        .map_err(|e| {
            match e {
                DbError::InsertAlreadyExists => failure(Response::FailedInsertion),
                _ => {
                    eprintln!("unexpected error: {}", e);
                    failure(Response::MiscError)
                }
            }
        })?;

    Ok(success(Response::Ok))
}

#[rocket::get("/api/<session>/tally/vote")]
fn get_ec_votes(state: State<'_, Api>, session: String) -> Json<WrappedResponse> {
    respond(get_ec_votes_inner(state, session))
}
fn get_ec_votes_inner(state: State<'_, Api>, session: String) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;
    let results = executor::block_on(state.db.get_all_enc_votes(&session))
        .map_err(|e| {
            eprintln!("Error: {}", e);
            failure(Response::MiscError)
        })?;
    Ok(success(Response::Ciphertexts(results)))
}

#[rocket::post("/api/<session>/tally/vote_mix", data = "<data>")]
fn post_ec_vote_mix(state: State<'_, Api>, content_type: &ContentType, session: String, data: Data) -> Json<WrappedResponse> {
    respond(post_ec_vote_mix_inner(state, content_type, session, data))
}
fn post_ec_vote_mix_inner(state: State<'_, Api>, content_type: &ContentType,  session: String, data: Data) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;

    // parse multipart form
    let options = MultipartFormDataOptions::with_multipart_form_data_fields(
        vec! [
            MultipartFormDataField::raw("msg").size_limit(1024 * 1024 * 40)
        ]
    );
    let mut data = MultipartFormData::parse(content_type, data, options)
        .map_err(|_| failure(Response::ParseError))?;
    let msg = data.raw.remove("msg")
        .ok_or(failure(Response::ParseError))?
        .remove(0);
    let msg: SignedMessage = serde_json::from_str(String::from_utf8(msg.raw)
            .map_err(|_| failure(Response::ParseError))?
            .as_str())
        .map_err(|_| failure(Response::ParseError))?;

    let (mix_index, enc_votes, enc_voter_ids, enc_as, enc_bs, enc_r_as, enc_r_bs, proof) = match &msg.inner {
        TrusteeMessage::EcVoteMix {
            mix_index, enc_votes, enc_voter_ids, enc_as, enc_bs, enc_r_as, enc_r_bs, proof
        } => {
            Ok((mix_index, enc_votes, enc_voter_ids, enc_as, enc_bs, enc_r_as, enc_r_bs, proof))
        },
        _ => Err(failure(Response::InvalidRequest))
    }?;

    let db = state.db.clone();

    // Verify the signature to ensure this was sent by an EC rep
    let trustee = executor::block_on(db.get_one_trustee_info(&session, &msg.sender_id))
        .map_err(|_| failure(Response::InvalidSignature))?;
    if !msg.verify(&trustee.pubkey).map_err(|_| failure(Response::MiscError))? {
        return Err(failure(Response::InvalidSignature));
    }

    executor::block_on(db.insert_ec_vote_mix(&session, *mix_index, &enc_votes, &enc_voter_ids, &enc_as, &enc_bs, &enc_r_as, &enc_r_bs, &proof, &msg.sender_id, &msg.signature))
        .map_err(|e| {
            match e {
                DbError::InsertAlreadyExists => failure(Response::FailedInsertion),
                _ => {
                    eprintln!("unexpected error: {}", e);
                    failure(Response::MiscError)
                }
            }
        })?;

    Ok(success(Response::Ok))
}

#[rocket::get("/api/<session>/tally/vote_mix/<mix_index>")]
fn get_ec_mix_votes(state: State<'_, Api>, session: String, mix_index: i16) -> Json<WrappedResponse> {
    respond(get_ec_mix_votes_inner(state, session, mix_index))
}
fn get_ec_mix_votes_inner(state: State<'_, Api>, session: String, mix_index: i16) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;
    let results = executor::block_on(state.db.get_mix_votes(&session, mix_index))
        .map_err(|e| {
            eprintln!("Error: {}", e);
            failure(Response::MiscError)
        })?;
    Ok(success(Response::Ciphertexts(results)))
}

#[rocket::post("/api/<session>/tally/mixed", data = "<data>")]
fn post_ec_vote_decrypt(state: State<'_, Api>, content_type: &ContentType, session: String, data: Data) -> Json<WrappedResponse> {
    respond(post_ec_vote_decrypt_inner(state, content_type, session, data))
}
fn post_ec_vote_decrypt_inner(state: State<'_, Api>, content_type: &ContentType,  session: String, data: Data) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;

    // parse multipart form
    let options = MultipartFormDataOptions::with_multipart_form_data_fields(
        vec! [
            MultipartFormDataField::raw("msg").size_limit(1024 * 1024 * 40)
        ]
    );
    let mut data = MultipartFormData::parse(content_type, data, options)
        .map_err(|_| failure(Response::ParseError))?;
    let msg = data.raw.remove("msg")
        .ok_or(failure(Response::ParseError))?
        .remove(0);
    let msg: SignedMessage = serde_json::from_str(String::from_utf8(msg.raw)
        .map_err(|_| failure(Response::ParseError))?
        .as_str())
        .map_err(|_| failure(Response::ParseError))?;

    let (signatures, shares) = match &msg.inner {
        TrusteeMessage::EcVoteDecrypt { signatures, shares} => Ok((signatures, shares)),
        _ => Err(failure(Response::InvalidRequest))
    }?;

    let db = state.db.clone();

    // Verify the signature to ensure this was sent by an EC trustee
    let trustee = executor::block_on(db.get_one_trustee_info(&session, &msg.sender_id))
        .map_err(|_| failure(Response::InvalidSignature))?;
    if !msg.verify(&trustee.pubkey).map_err(|_| failure(Response::MiscError))? {
        return Err(failure(Response::InvalidSignature));
    }

    executor::block_on(db.insert_ec_vote_decrypt(&session, &msg.sender_id, signatures, shares))
        .map_err(|e| {
            match e {
                DbError::InsertAlreadyExists => failure(Response::FailedInsertion),
                _ => {
                    eprintln!("unexpected error: {}", e);
                    failure(Response::MiscError)
                }
            }
        })?;

    Ok(success(Response::Ok))
}

#[rocket::get("/api/<session>/tally/mixed")]
fn get_ec_vote_decrypt(state: State<'_, Api>, session: String) -> Json<WrappedResponse> {
    respond(get_ec_vote_decrypt_inner(state, session))
}
fn get_ec_vote_decrypt_inner(state: State<'_, Api>, session: String) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;
    let results = executor::block_on(state.db.get_decrypt(&session))
        .map_err(|e| {
            eprintln!("Error: {}", e);
            failure(Response::MiscError)
        })?;
    Ok(success(Response::DecryptShares(results)))
}

#[rocket::get("/api/<session>/cast/ident")]
fn get_idents(state: State<'_, Api>, session: String) -> Json<WrappedResponse> {
    respond(get_idents_inner(state, session))
}
fn get_idents_inner(state: State<'_, Api>, session: String) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;
    let results = executor::block_on(state.db.get_all_idents(&session))
        .map_err(|e| {
            eprintln!("Error: {}", e);
            failure(Response::MiscError)
        })?;
    Ok(success(Response::Idents(results)))
}

#[rocket::get("/api/<session>/cast/commit")]
fn get_ec_commits(state: State<'_, Api>, session: String) -> Json<WrappedResponse> {
    respond(get_ec_commits_inner(state, session))
}
fn get_ec_commits_inner(state: State<'_, Api>, session: String) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;
    let results = executor::block_on(state.db.clone().get_all_ec_commits(&session))
        .map_err(|e| {
            eprintln!("Error: {}", e);
            failure(Response::MiscError)
        })?;
    Ok(success(Response::ResultSet(results)))
}

#[rocket::post("/api/<session>/tally/pet/commit", data = "<data>")]
fn post_pet_commits(state: State<'_, Api>, content_type: &ContentType, session: String, data: Data) -> Json<WrappedResponse> {
    respond(post_ec_pet_commits_inner(state, content_type, session, data))
}

fn post_ec_pet_commits_inner(state: State<'_, Api>, content_type: &ContentType,  session: String, data: Data) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;

    // parse multipart form
    let options = MultipartFormDataOptions::with_multipart_form_data_fields(
        vec! [
            MultipartFormDataField::raw("msg").size_limit(1024 * 1024 * 40)
        ]
    );
    let mut data = MultipartFormData::parse(content_type, data, options)
        .map_err(|_| failure(Response::ParseError))?;
    let msg = data.raw.remove("msg")
        .ok_or(failure(Response::ParseError))?
        .remove(0);
    let msg: SignedMessage = serde_json::from_str(String::from_utf8(msg.raw)
        .map_err(|_| failure(Response::ParseError))?
        .as_str())
        .map_err(|_| failure(Response::ParseError))?;

    let (voter_ids, vote_commits, mac_commits, signatures) = match &msg.inner {
        TrusteeMessage::EcPetCommit { voter_ids, vote_commits, mac_commits, signatures } => Ok((voter_ids, vote_commits, mac_commits, signatures)),
        _ => Err(failure(Response::InvalidRequest))
    }?;

    let db = state.db.clone();

    // Verify the signature to ensure this was sent by an EC rep
    let trustee = executor::block_on(db.get_one_trustee_info(&session, &msg.sender_id))
        .map_err(|_| failure(Response::InvalidSignature))?;
    if !msg.verify(&trustee.pubkey).map_err(|_| failure(Response::MiscError))? {
        return Err(failure(Response::InvalidSignature));
    }

    executor::block_on(db.insert_pet_commits(&session, &msg.sender_id, voter_ids, vote_commits, mac_commits, signatures))
        .map_err(|e| {
            match e {
                DbError::InsertAlreadyExists => failure(Response::FailedInsertion),
                _ => {
                    eprintln!("unexpected error: {}", e);
                    failure(Response::MiscError)
                }
            }
        })?;

    Ok(success(Response::Ok))
}

#[rocket::get("/api/<session>/tally/pet/commit/count")]
fn get_pet_commit_count(state: State<'_, Api>, session: String) -> Json<WrappedResponse> {
    respond(get_pet_commit_count_inner(state, session))
}
fn get_pet_commit_count_inner(state: State<'_, Api>, session: String) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;
    let results = executor::block_on(state.db.clone().count_pet_commits(&session))
        .map_err(|e| {
            eprintln!("Error: {}", e);
            failure(Response::MiscError)
        })?;
    Ok(success(Response::Count(results)))
}

#[rocket::get("/api/<session>/tally/pet/commit")]
fn get_pet_commits(state: State<'_, Api>, session: String) -> Json<WrappedResponse> {
    respond(get_pet_commits_inner(state, session))
}
fn get_pet_commits_inner(state: State<'_, Api>, session: String) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;
    let results = executor::block_on(state.db.clone().get_all_pet_commits(&session))
        .map_err(|e| {
            eprintln!("Error: {}", e);
            failure(Response::MiscError)
        })?;
    Ok(success(Response::PetCommits(results)))
}

#[rocket::post("/api/<session>/tally/pet/opening", data = "<data>")]
fn post_pet_openings(state: State<'_, Api>, content_type: &ContentType, session: String, data: Data) -> Json<WrappedResponse> {
    respond(post_pet_openings_inner(state, content_type, session, data))
}

fn post_pet_openings_inner(state: State<'_, Api>, content_type: &ContentType,  session: String, data: Data) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;

    // parse multipart form
    let options = MultipartFormDataOptions::with_multipart_form_data_fields(
        vec! [
            MultipartFormDataField::raw("msg").size_limit(1024 * 1024 * 40)
        ]
    );
    let mut data = MultipartFormData::parse(content_type, data, options)
        .map_err(|_| failure(Response::ParseError))?;
    let msg = data.raw.remove("msg")
        .ok_or(failure(Response::ParseError))?
        .remove(0);
    let msg: SignedMessage = serde_json::from_str(String::from_utf8(msg.raw)
        .map_err(|_| failure(Response::ParseError))?
        .as_str())
        .map_err(|_| failure(Response::ParseError))?;

    let (voter_ids, openings) = match &msg.inner {
        TrusteeMessage::EcPetOpening { voter_ids, openings } => Ok((voter_ids, openings)),
        _ => Err(failure(Response::InvalidRequest))
    }?;

    let db = state.db.clone();

    // Verify the signature to ensure this was sent by an EC rep
    let trustee = executor::block_on(db.get_one_trustee_info(&session, &msg.sender_id))
        .map_err(|_| failure(Response::InvalidSignature))?;
    if !msg.verify(&trustee.pubkey).map_err(|_| failure(Response::MiscError))? {
        return Err(failure(Response::InvalidSignature));
    }

    executor::block_on(db.insert_pet_openings(&session, &msg.sender_id, voter_ids, openings))
        .map_err(|e| {
            match e {
                DbError::InsertAlreadyExists => failure(Response::FailedInsertion),
                _ => {
                    eprintln!("unexpected error: {}", e);
                    failure(Response::MiscError)
                }
            }
        })?;

    Ok(success(Response::Ok))
}

#[rocket::get("/api/<session>/tally/pet/opening")]
fn get_pet_openings(state: State<'_, Api>, session: String) -> Json<WrappedResponse> {
    respond(get_pet_openings_inner(state, session))
}
fn get_pet_openings_inner(state: State<'_, Api>, session: String) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;
    let results = executor::block_on(state.db.clone().get_all_pet_openings(&session))
        .map_err(|e| {
            eprintln!("Error: {}", e);
            failure(Response::MiscError)
        })?;
    Ok(success(Response::PetOpenings(results)))
}

#[rocket::post("/api/<session>/tally/pet/decrypt", data = "<data>")]
fn post_pet_decryptions(state: State<'_, Api>, content_type: &ContentType, session: String, data: Data) -> Json<WrappedResponse> {
    respond(post_pet_decryptions_inner(state, content_type, session, data))
}

fn post_pet_decryptions_inner(state: State<'_, Api>, content_type: &ContentType,  session: String, data: Data) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;

    // parse multipart form
    let options = MultipartFormDataOptions::with_multipart_form_data_fields(
        vec! [
            MultipartFormDataField::raw("msg").size_limit(1024 * 1024 * 40)
        ]
    );
    let mut data = MultipartFormData::parse(content_type, data, options)
        .map_err(|_| failure(Response::ParseError))?;
    let msg = data.raw.remove("msg")
        .ok_or(failure(Response::ParseError))?
        .remove(0);
    let msg: SignedMessage = serde_json::from_str(String::from_utf8(msg.raw)
        .map_err(|_| failure(Response::ParseError))?
        .as_str())
        .map_err(|_| failure(Response::ParseError))?;

    let (voter_ids, shares) = match &msg.inner {
        TrusteeMessage::EcPetDecrypt { voter_ids, shares } => Ok((voter_ids, shares)),
        _ => Err(failure(Response::InvalidRequest))
    }?;

    let db = state.db.clone();

    // Verify the signature to ensure this was sent by an EC rep
    let trustee = executor::block_on(db.get_one_trustee_info(&session, &msg.sender_id))
        .map_err(|_| failure(Response::InvalidSignature))?;
    if !msg.verify(&trustee.pubkey).map_err(|_| failure(Response::MiscError))? {
        return Err(failure(Response::InvalidSignature));
    }

    executor::block_on(db.insert_pet_decrypt(&session, &msg.sender_id, voter_ids, shares))
        .map_err(|e| {
            match e {
                DbError::InsertAlreadyExists => failure(Response::FailedInsertion),
                _ => {
                    eprintln!("unexpected error: {}", e);
                    failure(Response::MiscError)
                }
            }
        })?;

    Ok(success(Response::Ok))
}

#[rocket::get("/api/<session>/tally/pet/decrypt")]
fn get_pet_decryptions(state: State<'_, Api>, session: String) -> Json<WrappedResponse> {
    respond(get_pet_decryptions_inner(state, session))
}
fn get_pet_decryptions_inner(state: State<'_, Api>, session: String) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;
    let results = executor::block_on(state.db.clone().get_all_pet_decryptions(&session))
        .map_err(|e| {
            eprintln!("Error: {}", e);
            failure(Response::MiscError)
        })?;
    Ok(success(Response::PetDecryptions(results)))
}
