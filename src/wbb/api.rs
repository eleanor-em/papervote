use std::sync::Arc;

use rocket::State;
use rocket_contrib::json::Json;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

use crate::common::sign::{SignedMessage, SigningPubKey};
use crate::trustee::TrusteeMessage;
use crate::wbb::db::{DbClient, DbError};
use eyre::Report;
use std::str::FromStr;
use futures::{executor, TryFutureExt};
use crate::voter::VoterMessage;
use crate::common::config::PapervoteConfig;
use crate::APP_NAME;

pub fn address(session_id: &Uuid, path: &str) -> String {
    let cfg: PapervoteConfig = confy::load(APP_NAME).unwrap();
    format!("{}{}{}", cfg.api_url, session_id, path)
}

pub struct Api {
    db: Arc<DbClient>,
}

impl Api {
    pub async fn new() -> Result<Self, Report> {
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
            ])
            .manage(self)
            .launch();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedResponse {
    pub status: bool,
    pub msg: Response,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    PublicKey(SigningPubKey),
    ResultSet(Vec<SignedMessage>),
    Ok,
    SessionExists,
    NotReady,
    UnknownId,
    TrusteeMissing,
    InvalidSession,
    InvalidData,
    InvalidRequest,
    InvalidSignature,
    FailedInsertion,
    ParseError,
    MiscError,
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

    let trustee_count = executor::block_on(state.db.get_trustee_count(&session).map_err(|_| failure(Response::InvalidSession)))?;
    let trustees = executor::block_on(state.db.count_trustees(&session).map_err(|_| failure(Response::InvalidSession)))?;
    if trustees < trustee_count {
        executor::block_on(state.db.insert_trustee(&session, &info.id, &info.pubkey, info.index, &info.address, &msg.signature))
            .map_err(|e| {
                eprintln!("error registering trustee: {}", e);
                failure(Response::InvalidData)
            })?;
        Ok(success(Response::Ok))
    } else {
        Err(failure(Response::InvalidRequest))
    }
}

#[derive(Serialize, Deserialize)]
pub struct NewSessionRequest {
    pub min_trustees: usize,
    pub trustee_count: usize,
}

#[rocket::post("/api/<session>/new", format = "json", data = "<req>")]
fn new_session(state: State<'_, Api>, session: String, req: Json<NewSessionRequest>) -> Json<WrappedResponse> {
    respond(new_session_inner(state, session, req))
}
fn new_session_inner(state: State<'_, Api>, session: String, req: Json<NewSessionRequest>) -> EitherResponse {
    let session = Uuid::from_str(&session).map_err(|_| failure(Response::InvalidSession))?;
    Ok(match executor::block_on(state.db.insert_session(&session, req.min_trustees, req.trustee_count)) {
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
    let trustee_count = executor::block_on(state.db.get_trustee_count(&session).map_err(|_| failure(Response::InvalidSession)))?;
    let trustee_info = executor::block_on(state.db.get_all_trustee_info(&session).map_err(|_| failure(Response::MiscError)))?;
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
    let info = executor::block_on(state.db.get_one_trustee_info(&session, &msg.sender_id)
        .map_err(|_| failure(Response::TrusteeMissing)))?;
    // Check signature
    match msg.verify(&info.pubkey) {
        Ok(true) => {
            // Add commitment
            executor::block_on(state.db.insert_commitment(&session, &info.id, &commitment, &msg.signature))
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
    let trustee_count = executor::block_on(state.db.get_trustee_count(&session).map_err(|_| failure(Response::InvalidSession)))?;
    let commitments = executor::block_on(state.db.get_all_commitments(&session))
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
    let pubkey = match &msg.inner {
        TrusteeMessage::KeygenSign { pubkey } => Ok(pubkey),
        _ => Err(failure(Response::InvalidRequest))
    }?;
    executor::block_on(state.db.insert_pubkey_sig(&session, &msg.sender_id, &pubkey, &msg.signature))
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
    let results = executor::block_on(state.db.get_all_pubkey_sigs(&session))
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

    let (voter_id, c_a, c_b) = match msg.into_inner() {
        VoterMessage::InitialCommit { voter_id, c_a, c_b } => Ok((voter_id, c_a, c_b)),
        _ => Err(failure(Response::InvalidRequest))
    }?;

    executor::block_on(state.db.insert_ident(&session, voter_id, &c_a, &c_b))
        .map(|_| success(Response::Ok))
        .map_err(|_| failure(Response::TrusteeMissing))
}

#[rocket::post("/api/<session>/cast/commit", format = "json", data = "<msg>")]
fn post_ec_commit(state: State<'_, Api>, session: String, msg: Json<SignedMessage>) -> Json<WrappedResponse> {
    respond(post_ec_commit_inner(state, session, msg))
}
fn post_ec_commit_inner(state: State<'_, Api>, session: String, msg: Json<SignedMessage>) -> EitherResponse {
    let session = Uuid::from_str(&session)
        .map_err(|_| failure(Response::InvalidSession))?;

    let (voter_id, enc_mac, enc_vote) = match &msg.inner {
        TrusteeMessage::EcCommit { voter_id, enc_mac, enc_vote } => Ok((voter_id, enc_mac, enc_vote)),
        _ => Err(failure(Response::InvalidRequest))
    }?;

    // Verify the signature to ensure this was sent by an EC rep
    let trustee = executor::block_on(state.db.get_one_trustee_info(&session, &msg.sender_id))
        .map_err(|_| failure(Response::InvalidSignature))?;
    if !msg.verify(&trustee.pubkey).map_err(|_| failure(Response::MiscError))? {
        return Err(failure(Response::InvalidSignature));
    }

    executor::block_on(state.db.insert_ec_commit(&session, voter_id.clone(), enc_mac, enc_vote, &msg.sender_id, &msg.signature))
        .map_err(|_| failure(Response::FailedInsertion))?;

    Ok(success(Response::Ok))
}