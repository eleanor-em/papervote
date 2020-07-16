use std::collections::HashMap;
use std::sync::{RwLock, Arc};

use cryptid::elgamal::CryptoContext;
use cryptid::CryptoError;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rocket::State;
use rocket_contrib::json::Json;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

use crate::sign;
use crate::sign::{SignedMessage, SigningPubKey};
use crate::trustee::{TrusteeMessage, TrusteeInfo};

pub struct Api {
    id: Uuid,
    keypair: Ed25519KeyPair,
    num_trustees: usize,
    trustee_info: Arc<RwLock<HashMap<Uuid, TrusteeInfo>>>,
    signed_trustee_info: Arc<RwLock<HashMap<Uuid, SignedMessage>>>,
    commitments: Arc<RwLock<HashMap<Uuid, SignedMessage>>>,
}

impl Api {
    pub fn new(num_trustees: usize, ctx: &CryptoContext) -> Result<Self, CryptoError> {
        let id = Uuid::new_v4();
        let keypair = sign::new_keypair(ctx.rng())?;

        let trustee_info = Arc::new(RwLock::new(HashMap::new()));
        let signed_trustee_info = Arc::new(RwLock::new(HashMap::new()));
        let commitments = Arc::new(RwLock::new(HashMap::new()));

        Ok(Self {
            id,
            keypair,
            num_trustees,
            trustee_info,
            signed_trustee_info,
            commitments
        })
    }

    fn sign(&self, message: TrusteeMessage) -> SignedMessage {
        let data = serde_json::to_string(&message).unwrap().as_bytes().to_vec();
        let signature = self.keypair.sign(&data).as_ref().to_vec();

        SignedMessage {
            inner: message,
            signature,
            sender_id: self.id,
        }
    }

    pub fn start(self) {
        rocket::ignite().mount("/", rocket::routes![
                get_pubkey,
                register_trustee,
                get_trustees,
                post_commitment,
                get_commitments,
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
    Receipt(SignedMessage),
    ResultSet(Vec<SignedMessage>),
    NotReady,
    UnknownId,
    InvalidRequest,
    InvalidSignature,
    MiscError,
}

#[rocket::get("/api/<_session>/pubkey")]
fn get_pubkey(state: State<'_, Api>, _session: String) -> Json<WrappedResponse> {
    Json(WrappedResponse {
        status: true,
        msg: Response::PublicKey(state.keypair.public_key().into()),
    })
}

#[rocket::post("/api/<_session>/trustee/register", format = "json", data = "<msg>")]
fn register_trustee(state: State<'_, Api>, _session: String, msg: Json<SignedMessage>) -> Json<WrappedResponse> {
    if let TrusteeMessage::Info { info } = &msg.inner {
        // Check we haven't filled up on trustees
        if state.trustee_info.read().unwrap().len() == state.num_trustees {
            return Json(WrappedResponse {
                status: false,
                msg: Response::InvalidRequest,
            });
        }

        // Verify the signature
        match msg.verify(&info.pubkey) {
            Ok(true) => {
                // Add the data
                state.trustee_info.write().unwrap().insert(info.id, info.clone());
                state.signed_trustee_info.write().unwrap().insert(info.id, msg.clone());

                // Sign the message to confirm receipt
                let signed_response = state.sign(msg.inner.clone());
                Json(WrappedResponse {
                    status: true,
                    msg: Response::Receipt(signed_response),
                })
            },
            Ok(false) => {
                // Signature did not match
                Json(WrappedResponse {
                    status: false,
                    msg: Response::InvalidSignature,
                })
            },
            Err(e) => {
                // Something weird happened
                eprintln!("Error: {}", e);
                Json(WrappedResponse {
                    status: false,
                    msg: Response::MiscError,
                })
            }
        }
    } else {
        Json(WrappedResponse {
            status: false,
            msg: Response::InvalidRequest
        })
    }
}

#[rocket::get("/api/<_session>/trustee/all")]
fn get_trustees(state: State<'_, Api>, _session: String) -> Json<WrappedResponse> {
    let signed_trustee_info = state.signed_trustee_info.read().unwrap();
    if signed_trustee_info.len() < state.num_trustees {
        Json(WrappedResponse {
            status: false,
            msg: Response::NotReady,
        })
    } else {
        Json(WrappedResponse {
            status: true,
            msg: Response::ResultSet(signed_trustee_info.values().map(|msg| msg.clone()).collect()),
        })
    }
}

#[rocket::post("/api/<_session>/keygen/commitment", format = "json", data = "<msg>")]
fn post_commitment(state: State<'_, Api>, _session: String, msg: Json<SignedMessage>) -> Json<WrappedResponse> {
    if let TrusteeMessage::KeygenCommit { .. } = &msg.inner {
        if let Some(info) = state.trustee_info.read().unwrap().get(&msg.sender_id) {
            // Check signature
            match msg.verify(&info.pubkey) {
                Ok(true) => {
                    // Add commitment
                    state.commitments.write().unwrap().insert(info.id, msg.clone());
                    let signed_response = state.sign(msg.inner.clone());
                    Json(WrappedResponse {
                        status: true,
                        msg: Response::Receipt(signed_response),
                    })
                },
                Ok(false) => {
                    // Signature failed verification
                    Json(WrappedResponse {
                        status: false,
                        msg: Response::InvalidSignature,
                    })
                }
                Err(e) => {
                    // Something weird happened
                    eprintln!("Error: {}", e);
                    Json(WrappedResponse {
                        status: false,
                        msg: Response::MiscError,
                    })
                }
            }
        } else {
            Json(WrappedResponse {
                status: false,
                msg: Response::UnknownId,
            })
        }
    } else {
        Json(WrappedResponse {
            status: false,
            msg: Response::InvalidRequest
        })
    }
}

#[rocket::get("/api/<_session>/keygen/commitment")]
fn get_commitments(state: State<'_, Api>, _session: String) -> Json<WrappedResponse> {
    let commitments = state.commitments.read().unwrap();
    if commitments.len() < state.num_trustees {
        Json(WrappedResponse {
            status: false,
            msg: Response::NotReady,
        })
    } else {
        Json(WrappedResponse {
            status: true,
            msg: Response::ResultSet(commitments.values().map(|msg| msg.clone()).collect()),
        })
    }
}