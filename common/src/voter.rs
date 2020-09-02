use cryptid::zkp::PrfKnowPlaintext;
use cryptid::elgamal::{Ciphertext, CurveElem};
use cryptid::{Scalar, CryptoError};
use std::convert::{TryInto, TryFrom};
use std::collections::HashMap;

use serde::{Serialize, Deserialize, de};
use cryptid::commit::Commitment;
use std::fmt::Display;
use serde::export::Formatter;
use std::fmt;
use itertools::Itertools;

pub fn write_default_candidates(path: &str) -> std::io::Result<()> {
    let alice = Candidate::new("Alice", 0);
    let bob = Candidate::new("Bob", 1);
    let carol = Candidate::new("Carol", 2);
    let dave = Candidate::new("Dave", 3);
    let edward = Candidate::new("Edward", 4);
    let fringilla = Candidate::new("Fringilla", 5);
    let gertrude = Candidate::new("Gertrude", 6);
    let mut candidates = HashMap::new();

    candidates.insert(alice.id(), alice.clone());
    candidates.insert(bob.id(), bob.clone());
    candidates.insert(carol.id(), carol.clone());
    candidates.insert(dave.id(), dave.clone());
    candidates.insert(edward.id(), edward.clone());
    candidates.insert(fringilla.id(), fringilla.clone());
    candidates.insert(gertrude.id(), gertrude.clone());

    candidates_to_file(&candidates, path)?;

    Ok(())
}

pub fn candidates_to_file(candidates: &HashMap<u64, Candidate>, path: &str) -> std::io::Result<()> {
    let mut keys = candidates.keys().collect_vec();
    keys.sort();
    let candidates = keys.into_iter()
        .map(|i| candidates[i].clone())
        .collect_vec();
    std::fs::write(path, serde_json::to_string(&candidates).unwrap())?;
    Ok(())
}

pub fn candidates_from_file(path: &str) -> Result<HashMap<u64, Candidate>, CandidateParseError> {
    let contents = std::fs::read_to_string(path)?;
    let candidates: Vec<Candidate> = serde_json::from_str(&contents)?;

    let mut result = HashMap::new();
    for candidate in candidates {
        result.insert(candidate.id, candidate);
    }

    Ok(result)
}

#[derive(Debug)]
pub enum CandidateParseError {
    Count,
    Id,
    Io(std::io::Error),
    Decode(serde_json::Error),
}

impl Display for CandidateParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CandidateParseError {}

impl From<std::io::Error> for CandidateParseError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for CandidateParseError {
    fn from(err: serde_json::Error) -> Self {
        Self::Decode(err)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Candidate {
    name: String,
    id: u64,
}

impl Candidate {
    pub fn new(name: &str, id: u64) -> Self {
        Self {
            name: name.to_string(),
            id,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Display for Candidate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.id, self.name)
    }
}

impl TryFrom<&str> for Candidate {
    type Error = CandidateParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut pieces = value.split(":").collect_vec();
        if pieces.len() < 2 {
            return Err(CandidateParseError::Count);
        }

        let id = pieces[0].parse::<u64>()
            .map_err(|_| CandidateParseError::Id)?;
        pieces.remove(0);

        let name = pieces.join(":");

        Ok(Self { id, name })
    }
}

// This bit sucks, but integers can't be keys in serde_json so we have to implement the
// ser/de traits ourselves
impl serde::Serialize for Candidate {
    fn serialize<S>(&self, serializer: S) -> Result<<S as serde::Serializer>::Ok, <S as serde::Serializer>::Error>
        where
            S: serde::Serializer {
        serializer.serialize_str(&self.to_string())
    }
}

pub struct CandidateVisitor;

impl<'de> de::Visitor<'de> for CandidateVisitor {
    type Value = Candidate;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("<id>:<name>")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error {
        Candidate::try_from(value)
            .map_err(|_| de::Error::custom("not a valid encoding"))
    }
}

impl<'de> serde::Deserialize<'de> for Candidate {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as serde::Deserializer<'de>>::Error>
        where
            D: serde::Deserializer<'de> {
        deserializer.deserialize_str(CandidateVisitor)
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct Vote {
    preferences: HashMap<Candidate, u64>,
}

// Only allow up to 36 candidate IDs for now

impl Vote {
    pub fn new() -> Self {
        Self { preferences: HashMap::new() }
    }

    pub fn contains(&self, preference: u64) -> bool {
        self.preferences.values().any(|val| *val == preference)
    }

    pub fn set(&mut self, candidate: &Candidate, preference: u64) {
        self.preferences.insert(candidate.clone(), preference);
    }

    pub fn from_string(encoded: &str, candidates: &HashMap<u64, Candidate>) -> Option<Self> {
        let mut preferences = HashMap::new();
        for (i, c) in encoded.chars().enumerate() {
            if let Some(pref) = char::to_digit(c, 36) {
                preferences.insert(candidates[&(i as u64)].clone(), pref as u64);
            } else {
                println!("failed at char #{}: {}", i, c);
                return None;
            }
        }

        Some(Self { preferences })
    }

    pub fn encode(&self) -> Scalar {
        let mut bytes = self.to_string().as_bytes().to_vec();
        if bytes.len() > 32 {
            panic!("Vote string too long!");
        }

        bytes.resize(32, 0);
        let mut array = [0; 32];
        array.clone_from_slice(&bytes);

        Scalar::from(array)
    }

    pub fn decode(value: Scalar, candidates: &HashMap<u64, Candidate>) -> Option<Self> {
        let bytes = value.to_bytes().to_vec()
            .into_iter()
            .filter(|c| c.is_ascii_digit())
            .collect();

        if let Ok(value) = String::from_utf8(bytes) {
            Self::from_string(&value, candidates)
        } else {
            None
        }
    }

    pub fn pretty(&self) -> String {
        let mut result = String::new();
        let mut selections = self.preferences.iter().collect_vec();
        selections.sort_by_key(|(candidate, _)| candidate.id);
        for (candidate, preference) in selections {
            result += &format!("\t{}: {}\n", candidate.name(), preference + 1);
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
            result.push(char::from_digit(self.preferences[&key] as u32, 36).unwrap());
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
    pub p1_prf_a: PrfKnowPlaintext,
    pub p1_prf_b: PrfKnowPlaintext,
    pub p1_prf_r_a: PrfKnowPlaintext,
    pub p1_prf_r_b: PrfKnowPlaintext,
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
        prf_know_mac: PrfKnowPlaintext,
        prf_know_vote: PrfKnowPlaintext,
    },
    Ballot(Ballot),
}

#[cfg(test)]
mod tests {
    use crate::voter::{VoterId, Vote, Candidate};
    use std::convert::TryFrom;
    use std::collections::HashMap;
    use rand::prelude::SliceRandom;

    #[test]
    fn test_voter_id_serde() {
        let id = VoterId("hello world".to_string());
        let encoded = id.try_as_curve_elem().unwrap();
        let decoded = VoterId::try_from(encoded).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_vote_serde() {
        let alice = Candidate::new("Alice", 0);
        let bob = Candidate::new("Bob", 1);
        let carol = Candidate::new("Carol", 2);
        let dave = Candidate::new("Dave", 3);
        let edward = Candidate::new("Edward", 4);
        let fringilla = Candidate::new("Fringilla", 5);
        let gertrude = Candidate::new("Gertrude", 6);
        let mut candidates = HashMap::new();
        candidates.insert(alice.id(), alice.clone());
        candidates.insert(bob.id(), bob.clone());
        candidates.insert(carol.id(), carol.clone());
        candidates.insert(dave.id(), dave.clone());
        candidates.insert(edward.id(), edward.clone());
        candidates.insert(fringilla.id(), fringilla.clone());
        candidates.insert(gertrude.id(), gertrude.clone());

        for _ in 0..100 {
            let mut prefs: Vec<_> = candidates.values().collect();
            prefs.shuffle(&mut rand::thread_rng());

            let mut vote = Vote::new();
            for (i, candidate) in prefs.iter().enumerate() {
                vote.set(candidate, i as u64);
            }

            let scalar = vote.encode();
            let vote2 = Vote::decode(scalar, &candidates).unwrap();

            assert_eq!(vote, vote2);
        }
    }
}
