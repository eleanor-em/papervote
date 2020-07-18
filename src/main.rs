#![feature(async_closure)]

use std::thread;

use cryptid::elgamal::CryptoContext;
use eyre::Result;
use papervote::APP_NAME;
use papervote::wbb::api::{Api, NewSessionRequest, WrappedResponse};
use uuid::Uuid;
use papervote::common::config::PapervoteConfig;
use papervote::trustee::Trustee;


#[tokio::main]
async fn main() -> Result<()> {
    let cfg: PapervoteConfig = confy::load(APP_NAME)?;
    let session_id = Uuid::new_v4();
    let ctx = CryptoContext::new();

    let min_trustees = cfg.min_trustees;
    let trustee_count = cfg.trustee_count;

    let api = Api::new().await?;
    thread::spawn(move || api.start());

    let client = reqwest::Client::new();
    let req = NewSessionRequest {
        min_trustees,
        trustee_count
    };
    let res: WrappedResponse = client.post(&format!("{}{}/new", cfg.api_url, session_id))
        .json(&req)
        .send().await?
        .json().await?;
    if !res.status {
        panic!("Failed opening session: {:?}", res.msg);
    }

    let mut futures = Vec::new();
    for index in 1..trustee_count + 1 {
        let session_id = session_id.clone();
        let ctx = ctx.cloned();
        futures.push(tokio::spawn(Trustee::new(session_id, ctx, index, min_trustees, trustee_count)));
    }

    let trustees: Vec<_> = futures.into_iter()
        .map(async move |future| future.await?)
        .collect();

    for trustee in trustees {
        let trustee = trustee.await?;
        println!("Hash: {}", trustee.hash_log());
    }

    Ok(())
}
