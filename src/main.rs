#![feature(async_closure)]
use std::collections::HashMap;
use std::sync::Arc;

use cryptid::elgamal::{CryptoContext, PublicKey};
use eyre::Result;
use rand::seq::SliceRandom;
use tokio::time::Duration;
use tokio::time;
use uuid::Uuid;

use papervote::APP_NAME;
use papervote::common::commit::PedersenCtx;
use papervote::common::config::PapervoteConfig;
use papervote::trustee::Trustee;
use papervote::voter::Voter;
use papervote::wbb::api::Api;
use papervote::common::vote::{Candidate, Vote};
use papervote::common::net::{WrappedResponse, NewSessionRequest};

#[tokio::main]
async fn main() -> Result<()> {
    // Setup
    let cfg: PapervoteConfig = confy::load(APP_NAME)?;
    let session_id = Uuid::new_v4();
    let ctx = CryptoContext::new();
    let commit_ctx = PedersenCtx::new(&session_id, ctx.clone());

    let api = Api::new().await?;
    std::thread::spawn(move || api.start());

    open_session(&cfg, session_id.clone()).await?;

    let candidates = get_candidates();
    let mut trustees = create_trustees(&cfg, ctx.clone(), session_id.clone()).await?;
    let pubkey = trustees[0].pubkey();

    let ec = &mut trustees[0];
    ec.receive_voter_data(candidates.clone());
    time::delay_for(Duration::from_millis(200)).await;

    let candidates: Vec<_> = candidates.values().collect();

    println!("Sending vote data...");
    let mut handles = Vec::new();
    const N: usize = 50;
    for i in 0..N {
        let addr = ec.address();
        let voter = random_voter(session_id.clone(), pubkey.clone(), ctx.clone(), commit_ctx.clone(), &candidates)?;
        handles.push(tokio::spawn(run_voter(voter, addr)));

        // give the threads a slight break to push through
        if i > 0 && i % 500 == 0 {
            time::delay_for(Duration::from_millis(1000)).await;
        }
    }

    futures::future::join_all(handles).await;

    println!("Votes closing soon...");
    ec.close_votes(N).await?;
    time::delay_for(Duration::from_millis(500)).await;

    Ok(())
}

async fn create_trustees(cfg: &PapervoteConfig, ctx: CryptoContext, session_id: Uuid) -> Result<Vec<Trustee>> {
    // Create trustees
    let mut futures = Vec::new();
    for index in 1..cfg.trustee_count + 1 {
        let session_id = session_id.clone();
        let ctx = ctx.clone();
        futures.push(tokio::spawn(Trustee::new(session_id, ctx, index, cfg.min_trustees, cfg.trustee_count)));
    }

    let mut trustees = Vec::new();

    for future in futures {
        let trustee = future.await??;
        trustees.push(trustee);
    }

    Ok(trustees)
}

async fn open_session(cfg: &PapervoteConfig, session_id: Uuid) -> Result<()> {
    let client = reqwest::Client::new();
    let req = NewSessionRequest {
        min_trustees: cfg.min_trustees,
        trustee_count: cfg.trustee_count,
    };

    let res: WrappedResponse = client.post(&format!("{}{}/new", cfg.api_url, session_id))
        .json(&req)
        .send().await?
        .json().await?;

    if !res.status {
        panic!("Failed opening session: {:?}", res.msg);
    }

    Ok(())
}

fn get_candidates() -> Arc<HashMap<usize, Candidate>> {
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
    Arc::new(candidates)
}

async fn run_voter(mut voter: Voter, addr: String) {
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
    println!("{}: voted", voter.id());
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
