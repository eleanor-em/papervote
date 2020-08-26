use eyre::Result;
use common::voter::VoterId;
use common::config::PapervoteConfig;
use common::APP_NAME;
use common::net::{Response, WrappedResponse};
use clap::{App, SubCommand};
use std::fmt::Display;
use serde::export::Formatter;
use std::fmt;
use reqwest::Client;
use std::io::Write;

#[derive(Debug)]
enum VerifyError {
    UnexpectedResponse,
    Api(Response),
}

impl Display for VerifyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for VerifyError {}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg: PapervoteConfig = confy::load(APP_NAME)?;

    let matches = App::new("Verifiable Vote-by-Mail: Verify")
        .version("0.1")
        .author("Eleanor McMurtry <elmcmurtry1@gmail.com>")
        .about("Verifies the result for the verifiable vote-by-mail protocol.")
        .subcommand(SubCommand::with_name("all")
            .about("Verifies all information, not just for one voter ID"))
        .get_matches();

    print!("Enter your voter ID: ");
    std::io::stdout().flush()?;

    let mut voter_id_input = String::new();
    std::io::stdin().read_line(&mut voter_id_input)?;
    let voter_id = VoterId::from(voter_id_input.trim().to_string());

    if let Some(_) = matches.subcommand_matches("all") {
        if !verify_all(&cfg).await? {
            return Ok(());
        }
    }

    verify_voter(&cfg, voter_id).await?;

    Ok(())
}

async fn get(client: &Client, cfg: &PapervoteConfig, path: &str) -> Result<Response> {
    let response: WrappedResponse = client.get(&format!("{}/{}{}", cfg.api_url, cfg.session_id, path))
        .send().await?
        .json().await?;

    if !response.status {
        Err(VerifyError::Api(response.msg))?
    } else {
        Ok(response.msg)
    }
}

async fn verify_voter(cfg: &PapervoteConfig, voter_id: VoterId) -> Result<()> {
    let client = Client::new();
    if let Response::AcceptedRows(rows) = get(&client, &cfg, "/tally/accepted").await? {
        if rows.into_iter().any(|row| row.voter_id == voter_id) {
            println!("Verification successful.");
        } else {
            println!("Verification failed.");
        }
    } else {
        return Err(VerifyError::UnexpectedResponse)?;
    }

    Ok(())
}

async fn verify_all(_cfg: &PapervoteConfig) -> Result<bool> {
    // TODO: Extend database code to be able to fetch all the proofs, and then check them.
    Ok(true)
}
