#![feature(async_closure)]

use std::thread;

use cryptid::elgamal::CryptoContext;
use eyre::Result;
use papervote::APP_NAME;
use papervote::wbb::api::{Api, NewSessionRequest, WrappedResponse, address};
use uuid::Uuid;
use papervote::common::config::PapervoteConfig;
use papervote::trustee::Trustee;
use papervote::voter::Voter;
use papervote::common::commit::PedersenCtx;
use papervote::voter::vote::{Vote, Candidate};


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
        let ctx = ctx.clone();
        futures.push(tokio::spawn(Trustee::new(session_id, ctx, index, min_trustees, trustee_count)));
    }

    let mut trustees = Vec::new();

    for future in futures {
        let trustee = future.await??;
        println!("Hash: {}", trustee.log());
        trustees.push(trustee);
    }

    let pubkey = trustees[0].pubkey();
    let alice = Candidate::new("Alice", 0);
    let bob = Candidate::new("Bob", 1);
    let carol = Candidate::new("Carol", 2);

    let commit_ctx = PedersenCtx::new(ctx.clone());

    let mut voter = Voter::new(pubkey, ctx.clone(), commit_ctx, "0".to_string())?;
    let mut vote = Vote::new();
    vote.set(&alice, 2);
    vote.set(&bob, 1);
    vote.set(&carol, 0);

    voter.set_vote(vote);

    let init_commit = voter.get_init_commit();
    let ec_commit = voter.get_ec_commit().unwrap();

    println!("{}", serde_json::to_string(&init_commit)?);
    println!("{}", serde_json::to_string(&ec_commit)?);

    let response: WrappedResponse = client.post(&address(&session_id, "/cast/ident"))
        .json(&init_commit).send().await?
        .json().await?;
    if !response.status {
        eprintln!("error submitting ident: {:?}", response.msg);
    }

    Ok(())
}
