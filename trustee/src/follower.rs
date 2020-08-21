use cryptid::elgamal::CryptoContext;
use common::config::PapervoteConfig;
use common::APP_NAME;
use eyre::Result;
use cryptid::commit::PedersenCtx;
use tokio::net::TcpListener;
use crate::{ControlMessage, Trustee};
use tokio::io::{BufReader, AsyncBufReadExt, BufWriter, AsyncWriteExt};

fn with_newline(msg: ControlMessage) -> Vec<u8> {
    format!("{}\n", serde_json::to_string(&msg).unwrap()).as_bytes().to_vec()
}

pub async fn run_follower(index: usize, port: u16) -> Result<()> {
    let cfg: PapervoteConfig = confy::load(APP_NAME)?;
    let ctx = CryptoContext::new()?;
    let commit_ctx = PedersenCtx::new(cfg.session_id.as_bytes());

    let mut listener = TcpListener::bind(&format!("127.0.0.1:{}", port)).await?;

    let (mut stream, _) = listener.accept().await?;
    let (read_stream, write_stream) = stream.split();

    let mut reader = BufReader::new(read_stream);
    let mut writer = BufWriter::new(write_stream);

    let mut buffer = String::new();
    reader.read_line(&mut buffer).await?;

    let mut trustee = if let Ok(ControlMessage::Begin) = serde_json::from_str(&buffer) {
        println!("creating trustee");
        Trustee::new(cfg.api_url.clone(), cfg.session_id, ctx, index, cfg.min_trustees, cfg.trustee_count).await?
    } else {
        panic!("unexpected message from leader");
    };

    writer.write_all(&with_newline(ControlMessage::Ok)).await?;
    writer.flush().await?;

    let mut buffer = String::new();
    reader.read_line(&mut buffer).await?;
    if let Ok(ControlMessage::FirstShuffle) = serde_json::from_str(&buffer) {
        println!("first shuffle");
        trustee.mix_votes().await?;
    } else {
        panic!("unexpected message from leader");
    };

    writer.write_all(&with_newline(ControlMessage::Ok)).await?;
    writer.flush().await?;

    let mut buffer = String::new();
    reader.read_line(&mut buffer).await?;

    Ok(())
}
