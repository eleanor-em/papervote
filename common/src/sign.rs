use serde::{Serialize, Deserialize};
use ring::signature;
use uuid::Uuid;
use std::fmt::Display;
use serde::export::Formatter;
use std::fmt;
use cryptid::{CryptoError, AsBase64};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::convert::TryFrom;
use crate::net::TrusteeMessage;
use cryptid::elgamal::CryptoContext;
use cryptid::base64_serde;
use rand::RngCore;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Signature(Vec<u8>);

impl AsBase64 for Signature {
    type Error = base64::DecodeError;

    fn as_base64(&self) -> String {
        base64::encode(&self.0)
    }

    fn try_from_base64(encoded: &str) -> Result<Self, Self::Error> {
        Ok(Self(base64::decode(encoded)?))
    }
}

base64_serde!(crate::sign::Signature);

#[derive(Debug)]
pub struct SigningKeypair(Ed25519KeyPair);

impl SigningKeypair {
    pub fn new(ctx: &CryptoContext) -> Self {
        let rng = ctx.rng();
        let mut rng = rng.lock().unwrap();
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        // Below call cannot fail
        Self(Ed25519KeyPair::from_seed_unchecked(&seed).unwrap())
    }

    pub fn sign(&self, bytes: &[u8]) -> Signature {
        Signature(self.0.sign(&bytes).as_ref().to_vec())
    }

    pub fn public_key(&self) -> SigningPubKey {
        self.0.public_key().into()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SignedMessage {
    pub inner: TrusteeMessage,
    pub signature: Signature,
    pub sender_id: Uuid,
}

impl SignedMessage {
    /// Verifies the signature of this message, assuming a particular public key.
    /// Returns true if the verification succeeds, false if it does not, and an error if
    /// serialisation fails.
    pub fn verify(&self, pub_key: &SigningPubKey) -> Result<bool, CryptoError> {
        let pub_key = signature::UnparsedPublicKey::new(&signature::ED25519, &pub_key.bytes);
        let ser = serde_json::to_string(&self.inner).map_err(|_| CryptoError::Misc).unwrap();
        Ok(match pub_key.verify(ser.as_bytes(), &self.signature.0) {
            Ok(_) => true,
            Err(_) => false,
        })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct SigningPubKey {
    pub bytes: Vec<u8>,
}

impl SigningPubKey {
    pub fn verify(&self, data: &[u8], signature: &Signature) -> bool {
        let pub_key = signature::UnparsedPublicKey::new(&signature::ED25519, &self.bytes);
        match pub_key.verify(data, &signature.0) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

impl Into<String> for SigningPubKey {
    fn into(self) -> String {
        base64::encode(&self.bytes)
    }
}

impl TryFrom<String> for SigningPubKey {
    type Error = base64::DecodeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: base64::decode(&value)?
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
