use eyre::Result;
use common::config::PapervoteConfig;
use tokio::io::{AsyncWriteExt, BufReader, AsyncBufReadExt};
use tokio::net::TcpStream;
use common::net::{NewSessionRequest, WrappedResponse};
use crate::{Trustee, ControlMessage};
use uuid::Uuid;
use cryptid::commit::PedersenCtx;
use cryptid::elgamal::CryptoContext;
use common::APP_NAME;
use tokio::time::Duration;
use tokio::time;
use std::sync::Arc;

fn with_newline(msg: ControlMessage) -> Vec<u8> {
    format!("{}\n", serde_json::to_string(&msg).unwrap()).as_bytes().to_vec()
}

pub async fn run_leader(index: usize, addresses: Vec<&str>) -> Result<()> {
    let cfg: PapervoteConfig = confy::load(APP_NAME)?;
    let candidates = common::voter::candidates_from_file(&cfg.candidate_file)?;
    let ctx = CryptoContext::new()?;
    let commit_ctx = PedersenCtx::new(cfg.session_id.as_bytes());

    open_session(&cfg, cfg.session_id.clone()).await?;

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

    // Create trustee
    for stream in streams.iter_mut() {
        stream.write_all(&with_newline(ControlMessage::Begin)).await?;
    }
    let mut trustee = Trustee::new(cfg.api_url.clone(), cfg.session_id, ctx, index, cfg.min_trustees, cfg.trustee_count).await?;
    wait_for_ok(&mut streams).await?;

    println!("Opening votes.");
    trustee.receive_voter_data(Arc::new(candidates));

    // For now, wait for input to close votes
    print!("Press Enter to close votes> ");
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer)?;

    trustee.close_votes().await?;

    for stream in streams.iter_mut() {
        stream.write_all(&with_newline(ControlMessage::FirstShuffle)).await?;
    }
    println!("first shuffle");
    trustee.mix_votes().await?;

    Ok(())
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
