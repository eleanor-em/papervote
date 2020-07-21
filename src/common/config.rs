use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct PapervoteConfig {
    pub min_trustees: usize,
    pub trustee_count: usize,
    pub db_host: String,
    pub db_user: String,
    pub db_pass: String,
    pub db_name: String,
    pub api_url: String,
    pub pedersen_h: String,
}

impl Default for PapervoteConfig {
    fn default() -> Self {
        Self {
            min_trustees: 2,
            trustee_count: 3,
            db_host: "localhost".to_string(),
            db_user: "postgres".to_string(),
            db_pass: "password".to_string(),
            db_name: "papervote".to_string(),
            api_url: "http://localhost:8000/api/".to_string(),
            // TODO: prove this isn't trapdoored
            pedersen_h: "ArDSLGmOZhHbBsbxvoLSjF0KYAsUMBYXkTTukhvkV1U=".to_string(),
        }
    }
}