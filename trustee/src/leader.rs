use eyre::Result;
use common::config::PapervoteConfig;
use tokio::io::{AsyncWriteExt, BufReader, AsyncBufReadExt};
use tokio::net::TcpStream;
use common::net::{NewSessionRequest, WrappedResponse, Response};
use crate::{Trustee, ControlMessage, TrusteeError};
use uuid::Uuid;
use cryptid::elgamal::CryptoContext;
use common::APP_NAME;
use tokio::time::Duration;
use tokio::time;
use std::sync::Arc;
use common::voter::{Vote, Candidate};
use std::collections::HashMap;

fn with_newline(msg: ControlMessage) -> Vec<u8> {
    format!("{}\n", serde_json::to_string(&msg).unwrap()).as_bytes().to_vec()
}

pub async fn run_leader(index: usize, addresses: Vec<&str>, from_file: Option<&str>) -> Result<()> {
    let cfg: PapervoteConfig = confy::load(APP_NAME)?;
    let candidates = common::voter::candidates_from_file(&cfg.candidate_file)?;
    let candidates = Arc::new(candidates);
    let ctx = CryptoContext::new()?;

    let mut streams = Vec::new();
    for address in addresses {
        loop {
            if let Ok(stream) = TcpStream::connect(address).await {
                streams.push(stream);
                break;
            }

            time::delay_for(Duration::from_millis(1000)).await;
        }
    }

    let mut trustee = match from_file {
        None => run_leader_gen(&cfg, &ctx, candidates.clone(), &mut streams, index).await?,
        Some(file) => run_leader_existing(&cfg, &ctx, &mut streams, index, file).await?,
    };

    println!("Opening votes.");
    trustee.receive_voter_data(candidates.clone());

    // For now, wait for input to close votes
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer)?;

    trustee.close_votes().await?;

    // First shuffle
    println!("first shuffle");
    trustee.mix_votes().await?;

    // Shuffle in order
    for stream in streams.iter_mut() {
        stream.write_all(&with_newline(ControlMessage::FirstShuffle)).await?;

        let mut reader = BufReader::new(stream);
        let mut buffer = String::new();
        reader.read_line(&mut buffer).await?;

        match serde_json::from_str(&buffer) {
            Ok(ControlMessage::Ok) => { /* ok */ },
            Ok(msg) => { eprintln!("unexpected message from follower: {:?}", msg) },
            Err(e) => { eprintln!("error receiving follower message: {}", e) }
        }
    }

    // First decrypt
    for stream in streams.iter_mut() {
        stream.write_all(&with_newline(ControlMessage::FirstDecrypt)).await?;
    }
    println!("first decrypt");
    trustee.decrypt_first_mix().await?;
    wait_for_ok(&mut streams).await?;

    // PET commits
    for stream in streams.iter_mut() {
        stream.write_all(&with_newline(ControlMessage::PetCommit)).await?;
    }
    println!("PET commits");
    let pet_instances = trustee.validate_votes().await?;
    let pet_data = trustee.do_pet_commits(pet_instances).await?;
    wait_for_ok(&mut streams).await?;

    // PET openings
    for stream in streams.iter_mut() {
        stream.write_all(&with_newline(ControlMessage::PetOpenCommits)).await?;
    }
    println!("PET openings");
    let data = trustee.do_pet_openings(pet_data).await?;
    wait_for_ok(&mut streams).await?;

    // PET decryptions
    for stream in streams.iter_mut() {
        stream.write_all(&with_newline(ControlMessage::PetDecrypt)).await?;
    }
    println!("PET decryptions");
    let ciphertexts = trustee.do_pet_decryptions(data).await?;
    wait_for_ok(&mut streams).await?;

    // Post accepted votes
    trustee.finish_pets(ciphertexts).await?;

    // Last shuffle
    println!("last shuffle");
    trustee.mix_accepted().await?;
    // Shuffle in order
    for stream in streams.iter_mut() {
        stream.write_all(&with_newline(ControlMessage::LastShuffle)).await?;

        let mut reader = BufReader::new(stream);
        let mut buffer = String::new();
        reader.read_line(&mut buffer).await?;

        match serde_json::from_str(&buffer) {
            Ok(ControlMessage::Ok) => { /* ok */ },
            Ok(msg) => { eprintln!("unexpected message from follower: {:?}", msg) },
            Err(e) => { eprintln!("error receiving follower message: {}", e) }
        }
    }

    // Last decryptions
    for stream in streams.iter_mut() {
        stream.write_all(&with_newline(ControlMessage::LastDecrypt)).await?;
    }
    println!("last decryptions");
    trustee.decrypt_accepted().await?;
    wait_for_ok(&mut streams).await?;

    // Produce accepted votes
    trustee.finish(&candidates).await?;
    let votes = get_tally(&cfg).await?;
    for vote in votes {
        println!("{}", vote.pretty());
    }

    Ok(())
}

pub async fn run_leader_gen(cfg: &PapervoteConfig, ctx: &CryptoContext, candidates: Arc<HashMap<u64, Candidate>>, mut streams: &mut [TcpStream], index: usize) -> Result<Trustee> {
    open_session(&cfg, cfg.session_id.clone()).await?;

    // Create trustee
    for stream in streams.iter_mut() {
        stream.write_all(&with_newline(ControlMessage::Begin)).await?;
    }
    let mut trustee = Trustee::new(cfg.api_url.clone(), cfg.trustee_advertised_url.clone(),
                                   cfg.session_id, ctx.clone(), index, cfg.min_trustees, cfg.trustee_count).await?;
    wait_for_ok(&mut streams).await?;
    Ok(trustee)
}

pub async fn run_leader_existing(cfg: &PapervoteConfig, ctx: &CryptoContext, mut streams: &mut[TcpStream], index: usize, file: &str) -> Result<Trustee> {
    let trustee = Trustee::from_file(cfg.api_url.clone(), cfg.trustee_advertised_url.clone(),
                                         cfg.session_id, ctx.clone(), index, cfg.min_trustees, cfg.trustee_count, file).await?;
    for stream in streams.iter_mut() {
        stream.write_all(&with_newline(ControlMessage::Begin)).await?;
        stream.flush().await?;
    }
    wait_for_ok(&mut streams).await?;
    Ok(trustee)
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

async fn wait_for_ok(streams: &mut [TcpStream]) -> Result<()> {
    for stream in streams.iter_mut() {
        let mut reader = BufReader::new(stream);
        let mut buffer = String::new();
        reader.read_line(&mut buffer).await?;

        match serde_json::from_str(&buffer) {
            Ok(ControlMessage::Ok) => { /* ok */ },
            Ok(msg) => { eprintln!("unexpected message from follower: {:?}", msg) },
            Err(e) => { eprintln!("error receiving follower message: {}", e) }
        }
    }

    Ok(())
}

async fn get_tally(
    cfg: &PapervoteConfig
) -> Result<Vec<Vote>, TrusteeError> {
    let client = reqwest::Client::new();

    let response: WrappedResponse = client.get(&format!("{}/{}/tally/final", cfg.api_url, cfg.session_id))
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
