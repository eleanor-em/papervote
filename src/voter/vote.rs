use std::collections::HashMap;

use serde::{Serialize, Deserialize};

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