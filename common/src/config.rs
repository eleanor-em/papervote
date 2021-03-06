use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct PapervoteConfig {
    pub min_trustees: usize,
    pub trustee_count: usize,
    pub db_host: String,
    pub db_user: String,
    pub db_pass: String,
    pub db_name: String,
    pub api_url: String,
    pub trustee_advertised_url: String,
    pub candidate_file: String,
    pub session_id: Uuid,
    pub debug_mode: bool,
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
            api_url: "http://115.146.93.101:8001/api".to_string(),
            trustee_advertised_url: "115.146.93.101".to_string(),
            candidate_file: "candidates.json".to_string(),
            // session_id: Uuid::new_v4(),
            session_id: Uuid::parse_str("86ee2bfe-4677-4398-9e61-ad9087fc3117").unwrap(),
            debug_mode: true,
        }
    }
}