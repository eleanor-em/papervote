use serde::{Serialize, Deserialize};
use ring::signature;
use uuid::Uuid;
use std::fmt::Display;
use serde::export::Formatter;
use std::fmt;
use cryptid::CryptoError;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::sync::{Arc, Mutex};
use ring::rand::SystemRandom;
use std::ops::Deref;
use crate::trustee::TrusteeMessage;
use std::convert::TryFrom;

pub type SigningKeypair = Ed25519KeyPair;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SignedMessage {
    pub inner: TrusteeMessage,
    pub signature: Vec<u8>,
    pub sender_id: Uuid,
}

impl SignedMessage {
    /// Verifies the signature of this message, assuming a particular public key.
    /// Returns true if the verification succeeds, false if it does not, and an error if
    /// serialisation fails.
    pub fn verify(&self, pub_key: &SigningPubKey) -> Result<bool, CryptoError> {
        let pub_key = signature::UnparsedPublicKey::new(&signature::ED25519, &pub_key.bytes);
        let ser = serde_json::to_string(&self.inner).map_err(|_| CryptoError::Misc).unwrap();
        Ok(match pub_key.verify(ser.as_bytes(), self.signature.as_ref()) {
            Ok(_) => true,
            Err(_) => false,
        })
    }
}

pub fn new_keypair(rng: Arc<Mutex<SystemRandom>>) -> Result<SigningKeypair, CryptoError> {
    let rng = rng.lock().unwrap();
    let bytes = signature::Ed25519KeyPair::generate_pkcs8(rng.deref())
        .map_err(|e| CryptoError::Unspecified(e))?;
    signature::Ed25519KeyPair::from_pkcs8(bytes.as_ref())
        .map_err(|e| CryptoError::KeyRejected(e))
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct SigningPubKey {
    pub bytes: Vec<u8>,
}

impl Into<String> for SigningPubKey {
    fn into(self) -> String {
        base64::encode(self.bytes)
    }
}

impl TryFrom<String> for SigningPubKey {
    type Error = base64::DecodeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: base64::decode(value)?
        })
    }
}

impl From<&<Ed25519KeyPair as KeyPair>::PublicKey> for SigningPubKey {
    fn from(key: &<Ed25519KeyPair as KeyPair>::PublicKey) -> Self {
        Self { bytes: key.as_ref().to_vec() }
    }
}

impl Display for SigningPubKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base64::encode(&self.bytes))
    }
}
