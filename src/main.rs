#![feature(async_closure)]

use std::thread;

use cryptid::elgamal::{CryptoContext, PublicKey};
use eyre::Result;
use papervote::APP_NAME;
use papervote::wbb::api::{Api, NewSessionRequest, WrappedResponse};
use uuid::Uuid;
use papervote::common::config::PapervoteConfig;
use papervote::trustee::Trustee;
use papervote::voter::Voter;
use papervote::common::commit::PedersenCtx;
use papervote::voter::vote::{Vote, Candidate};
use std::collections::HashMap;
use std::sync::Arc;
use rand::seq::SliceRandom;
use tokio::time::Duration;
use tokio::time;

#[tokio::main]
async fn main() -> Result<()> {
    // Setup
    let cfg: PapervoteConfig = confy::load(APP_NAME)?;
    let session_id = Uuid::new_v4();
    let ctx = CryptoContext::new();

    let min_trustees = cfg.min_trustees;
    let trustee_count = cfg.trustee_count;

    // Start web listener
    let api = Api::new().await?;
    thread::spawn(move || api.start());

    // Open session
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

    println!("Creating trustees...");
    // Create trustees
    let mut futures = Vec::new();
    for index in 1..trustee_count + 1 {
        let session_id = session_id.clone();
        let ctx = ctx.clone();
        futures.push(tokio::spawn(Trustee::new(session_id, ctx, index, min_trustees, trustee_count)));
    }

    let mut trustees = Vec::new();

    for future in futures {
        let trustee = future.await??;
        trustees.push(trustee);
    }


    // Produce election parameters
    let pubkey = trustees[0].pubkey();
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
    let candidates = Arc::new(candidates);
    println!("Creating parameters...");

    // Let the EC begin listening
    let ec = &mut trustees[0];
    ec.receive_voter_data(candidates.clone());
    // Wait for EC to start properly
    time::delay_for(Duration::from_millis(200)).await;

    let commit_ctx = PedersenCtx::new(ctx.clone());
    let candidates: Vec<_> = candidates.values().collect();

    println!("Sending vote data...");
    let mut handles = Vec::new();
    const N: usize = 10000;
    for i in 0..N {
        let addr = ec.address();
        let voter = random_voter(session_id.clone(), pubkey.clone(), ctx.clone(), commit_ctx.clone(), &candidates)?;
        handles.push(tokio::spawn(run_voter(voter, addr)));

        // give the threads a slight break to push through
        if i > 0 && i % 1000 == 0 {
            time::delay_for(Duration::from_millis(1000)).await;
        }
    }

    futures::future::join_all(handles).await;

    println!("Votes closing soon...");
    ec.close_votes(N).await?;

    Ok(())
}

async fn run_voter(mut voter: Voter, addr: String) -> Result<()> {
    const DELAY: u64 = 1000;

    while let Err(_) = voter.post_init_commit().await {
        println!("{}: retrying ident", voter.id());
        time::delay_for(Duration::from_millis(DELAY)).await;
    }

    loop {
        if let Ok(()) = voter.post_ec_commit(&addr).await {
            if let Ok(()) = voter.check_ec_commit().await {
                break;
            }
        }
        println!("{}: retrying commit", voter.id());
        time::delay_for(Duration::from_millis(DELAY)).await;
    }

    while let Err(_) = voter.post_vote(&addr).await{
        println!("{}: retrying vote", voter.id());
        time::delay_for(Duration::from_millis(DELAY)).await;
    }

    Ok(())

}

fn random_voter(session_id: Uuid, pubkey: PublicKey, ctx: CryptoContext, commit_ctx: PedersenCtx, candidates: &[&Candidate]) -> Result<Voter> {
    let mut prefs: Vec<_> = candidates.iter().enumerate().map(|(_, candidate)| candidate.clone()).collect();
    prefs.shuffle(&mut rand::thread_rng());

    let id = base64::encode(Uuid::new_v4().as_bytes()).replace("/", "");
    let mut voter = Voter::new(session_id.clone(), pubkey, ctx.clone(), commit_ctx, id)?;
    let mut vote = Vote::new();
    for (i, candidate) in prefs.iter().enumerate() {
        vote.set(candidate, i);
    }
    voter.set_vote(vote);

    Ok(voter)
}
