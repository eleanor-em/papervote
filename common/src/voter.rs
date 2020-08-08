use cryptid::zkp::PrfKnowDlog;
use cryptid::elgamal::{Ciphertext, CurveElem};
use cryptid::{Scalar, CryptoError};
use std::convert::{TryInto, TryFrom};
use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use cryptid::commit::Commitment;
use std::fmt::Display;
use serde::export::Formatter;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct Candidate {
    name: String,
    id: usize,
}

impl Candidate {
    pub fn new(name: &str, id: usize) -> Self {
        Self {
            name: name.to_string(), id
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn id(&self) -> usize {
        self.id
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Vote {
    preferences: HashMap<Candidate, usize>,
}

// Only allow up to 36 candidate IDs for now

impl Vote {
    pub fn new() -> Self {
        Self { preferences: HashMap::new() }
    }

    pub fn set(&mut self, candidate: &Candidate, preference: usize) {
        self.preferences.insert(candidate.clone(), preference);
    }

    pub fn from_string(encoded: &str, candidates: &HashMap<usize, Candidate>) -> Option<Self> {
        let mut preferences = HashMap::new();
        for (i, c) in encoded.chars().enumerate() {
            if let Some(pref) = char::to_digit(c, 10) {
                preferences.insert(candidates[&i].clone(), pref as usize);
            } else {
                return None;
            }
        }

        Some(Self { preferences })
    }

    pub fn pretty(&self) -> String {
        let mut reversed = self.preferences.iter().collect::<Vec<_>>();
        reversed.sort_by_key(|(_, key)| **key);
        let reversed = reversed.into_iter()
            .map(|(candidate, key)| (key + 1, candidate))
            .collect::<Vec<_>>();

        let mut result = String::new();
        for (preference, candidate) in reversed.into_iter() {
            result += &format!("\t{}. {}\n", preference, candidate.name());
        }

        result
    }
}

impl ToString for Vote {
    fn to_string(&self) -> String {
        let mut result = Vec::new();
        let mut keys: Vec<_> = self.preferences.keys().collect();
        keys.sort_by_key(|candidate| candidate.id);

        for key in keys {
            result.push(char::from_digit(self.preferences[&key] as u32, 10).unwrap());
        }
        result.into_iter().collect()
    }
}
#[derive(Hash, Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct VoterId(String);

impl Display for VoterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for VoterId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl TryFrom<CurveElem> for VoterId {
    type Error = CryptoError;

    fn try_from(value: CurveElem) -> Result<Self, Self::Error> {
        let scalar = value.decoded()?;
        let mut bytes = scalar.as_bytes().to_vec();
        // assume null terminated
        for i in 0..bytes.len() {
            if bytes[i] == 0 {
                bytes.truncate(i);
                break;
            }
        }

        Ok(Self(String::from_utf8(bytes).map_err(|_| CryptoError::Decoding)?))
    }
}

impl VoterId {
    pub fn new(src: String) -> Self {
        Self(src)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn try_as_curve_elem(&self) -> Option<CurveElem> {
        CurveElem::try_encode(self.0.as_bytes().to_vec().try_into().ok()?).ok()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Ballot {
    pub p1_vote: String,
    pub p1_enc_a: Ciphertext,
    pub p1_enc_b: Ciphertext,
    pub p1_enc_r_a: Ciphertext,
    pub p1_enc_r_b: Ciphertext,
    pub p1_prf_a: PrfKnowDlog,
    pub p1_prf_b: PrfKnowDlog,
    pub p1_prf_r_a: PrfKnowDlog,
    pub p1_prf_r_b: PrfKnowDlog,
    pub p2_id: VoterId,
    pub p2_enc_id: Ciphertext,
    pub p2_prf_enc: Scalar,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct VoterIdent {
    pub id: VoterId,
    pub c_a: Commitment,
    pub c_b: Commitment,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum VoterMessage {
    InitialCommit(VoterIdent),
    EcCommit {
        voter_id: VoterId,
        enc_mac: Ciphertext,
        enc_vote: Ciphertext,
        prf_know_mac: PrfKnowDlog,
        prf_know_vote: PrfKnowDlog,
    },
    Ballot(Ballot),
}

#[cfg(test)]
mod tests {
    use crate::voter::VoterId;
    use std::convert::TryFrom;

    #[test]
    fn test_voter_id_serde() {
        let id = VoterId("hello world".to_string());
        let encoded = id.try_as_curve_elem().unwrap();
        let decoded = VoterId::try_from(encoded).unwrap();
        assert_eq!(id, decoded);
    }
}
