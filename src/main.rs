#![feature(async_closure)]
use std::collections::HashMap;
use std::sync::Arc;

use cryptid::elgamal::{CryptoContext, PublicKey};
use eyre::Result;
use rand::seq::SliceRandom;
use tokio::time::Duration;
use tokio::time;
use uuid::Uuid;

use common::APP_NAME;
use common::config::PapervoteConfig;
use common::voter::{Candidate, Vote, candidates_from_file};
use common::net::{WrappedResponse, NewSessionRequest, Response};
use trustee::{Trustee, TrusteeError};
use voter::Voter;
use cryptid::commit::PedersenCtx;

#[tokio::main]
async fn main() -> Result<()> {
    // Setup
    let cfg: PapervoteConfig = confy::load(APP_NAME)?;
    let ctx = CryptoContext::new()?;
    let commit_ctx = PedersenCtx::new(cfg.session_id.as_bytes());

    // Create a new election session
    open_session(&cfg, cfg.session_id.clone()).await?;

    // Build the candidate list
    let candidate_map = Arc::new(candidates_from_file(&cfg.candidate_file)?);

    // Create the trustees and run key generation
    let mut trustees = create_trustees(&cfg, ctx.clone(), cfg.session_id.clone()).await?;
    let pubkey = trustees[0].pubkey();

    // Start listening for votes
    let ec = &mut trustees[0];
    ec.receive_voter_data(candidate_map.clone());
    time::delay_for(Duration::from_millis(200)).await;

    // Send votes
    println!("Sending vote data...");
    let mut handles = Vec::new();

    const N: usize = 100;
    for i in 0..N {
        let addr = ec.address();
        let voter = random_voter(cfg.session_id.clone(), pubkey.clone(), ctx.clone(), commit_ctx.clone(), &candidate_map)?;
        handles.push(tokio::spawn(run_voter(voter, cfg.api_url.clone(), addr)));

        // give the threads a slight break to push through
        if i > 0 && i % 500 == 0 {
            time::delay_for(Duration::from_millis(1000)).await;
        }
    }

    futures::future::join_all(handles).await;

    // Close vote listener
    println!("Votes closing soon...");
    time::delay_for(Duration::from_millis(1000)).await;
    ec.close_votes().await?;

    // Run first shuffle
    for trustee in trustees.iter_mut() {
        trustee.mix_votes().await?;
        println!("shuffle #{} done", trustee.index());
    }

    // Run first decryption
    for trustee in trustees.iter_mut() {
        trustee.decrypt_first_mix().await?;
        println!("decrypt #{} done", trustee.index());
    }

    // Run data matching
    let pet_instances = trustees[0].validate_votes().await?;

    // Run PET commitments
    let mut pet_data = Vec::new();
    for trustee in trustees.iter_mut() {
        pet_data.push(trustee.do_pet_commits(pet_instances.clone()).await?);
        println!("PET commit #{} done", trustee.index());
    }

    // Run PET openings
    let mut pet_records = Vec::new();
    for (trustee, data) in trustees.iter_mut().zip(pet_data.into_iter()) {
        pet_records.push(trustee.do_pet_openings(data).await?);
        println!("PET opening #{} done", trustee.index());
    }

    // Run PET decryptions
    let mut ciphertexts = HashMap::new();
    for (trustee, data) in trustees.iter_mut().zip(pet_records.into_iter()) {
        ciphertexts = trustee.do_pet_decryptions(data).await?;
        println!("PET decryption #{} done", trustee.index());
    }

    // Post accepted votes
    trustees[0].finish_pets(ciphertexts).await?;

    // Run last shuffle
    for trustee in trustees.iter_mut() {
        trustee.mix_accepted().await?;
        println!("shuffle #{} done", trustee.index());
    }

    // Decrypt final tally
    for trustee in trustees.iter_mut() {
        trustee.decrypt_accepted().await?;
        println!("decryption #{} done", trustee.index());
    }

    // Produce votes
    trustees[0].finish(&candidate_map).await?;
    println!("Tally uploaded.");

    let votes = get_tally(&cfg, &cfg.session_id).await?;
    println!("{} votes counted.", votes.len());

    Ok(())
}

async fn create_trustees(cfg: &PapervoteConfig, ctx: CryptoContext, session_id: Uuid) -> Result<Vec<Trustee>> {
    // Create trustees
    let mut futures = Vec::new();
    for index in 1..cfg.trustee_count + 1 {
        let session_id = session_id.clone();
        let ctx = ctx.clone();
        futures.push(tokio::spawn(Trustee::new(cfg.api_url.clone(), session_id, ctx, index, cfg.min_trustees, cfg.trustee_count)));
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

    let res: WrappedResponse = client.post(&format!("{}/{}/new", cfg.api_url, session_id))
        .json(&req)
        .send().await?
        .json().await?;

    if !res.status {
        panic!("Failed opening session: {:?}", res.msg);
    }

    Ok(())
}

async fn run_voter(mut voter: Voter, api_base_addr: String, addr: String) {
    const DELAY: u64 = 1000;

    while let Err(_) = voter.post_init_commit(&api_base_addr).await {
        println!("{}: retrying ident", voter.id());
        time::delay_for(Duration::from_millis(DELAY)).await;
    }

    loop {
        if let Ok(()) = voter.post_ec_commit(&addr).await {
            if let Ok(()) = voter.check_ec_commit(&api_base_addr).await {
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

fn random_voter(session_id: Uuid, pubkey: PublicKey, ctx: CryptoContext, commit_ctx: PedersenCtx, candidates: &HashMap<u64, Candidate>) -> Result<Voter> {
    let mut prefs: Vec<_> = candidates.values().collect();
    prefs.shuffle(&mut rand::thread_rng());

    let id = base64::encode(Uuid::new_v4().as_bytes()).replace("/", "-");
    let mut voter = Voter::new(session_id.clone(), pubkey, ctx.clone(), commit_ctx, id)?;
    let mut vote = Vote::new();
    for (i, candidate) in prefs.iter().enumerate() {
        vote.set(candidate, i as u64);
    }

    voter.set_vote(vote);

    Ok(voter)
}

pub async fn get_tally(
    cfg: &PapervoteConfig,
    session_id: &Uuid
) -> Result<Vec<Vote>, TrusteeError> {
    let client = reqwest::Client::new();

    let response: WrappedResponse = client.get(&format!("{}/{}/tally/final", cfg.api_url, session_id))
        .send().await?
        .json().await?;

    if !response.status {
        return Err(TrusteeError::FailedResponse(response.msg));
    }

    match response.msg {
        Response::Votes(results) => Ok(results),
        _ => Err(TrusteeError::InvalidResponse)
    }
}
