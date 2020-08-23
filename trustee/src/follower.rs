use cryptid::elgamal::CryptoContext;
use common::config::PapervoteConfig;
use common::APP_NAME;
use eyre::Result;
use tokio::net::TcpListener;
use crate::{ControlMessage, Trustee};
use tokio::io::{BufReader, AsyncBufReadExt, BufWriter, AsyncWriteExt};

fn with_newline(msg: ControlMessage) -> Vec<u8> {
    format!("{}\n", serde_json::to_string(&msg).unwrap()).as_bytes().to_vec()
}

pub async fn run_follower(index: usize, port: u16) -> Result<()> {
    let cfg: PapervoteConfig = confy::load(APP_NAME)?;
    let ctx = CryptoContext::new()?;

    let mut listener = TcpListener::bind(&format!("127.0.0.1:{}", port)).await?;

    let (mut stream, _) = listener.accept().await?;
    let (read_stream, write_stream) = stream.split();

    let mut reader = BufReader::new(read_stream);
    let mut writer = BufWriter::new(write_stream);

    let mut buffer = String::new();
    reader.read_line(&mut buffer).await?;

    let mut trustee = if let Ok(ControlMessage::Begin) = serde_json::from_str(&buffer) {
        println!("creating trustee");
        Trustee::new(cfg.api_url.clone(), cfg.trustee_advertised_url.clone(),
                     cfg.session_id, ctx, index, cfg.min_trustees, cfg.trustee_count).await?
    } else {
        panic!("unexpected message from leader");
    };

    writer.write_all(&with_newline(ControlMessage::Ok)).await?;
    writer.flush().await?;

    // First shuffle
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

    // First decrypt
    let mut buffer = String::new();
    reader.read_line(&mut buffer).await?;
    if let Ok(ControlMessage::FirstDecrypt) = serde_json::from_str(&buffer) {
        println!("first decrypt");
        trustee.decrypt_first_mix().await?;
    } else {
        panic!("unexpected message from leader");
    };

    writer.write_all(&with_newline(ControlMessage::Ok)).await?;
    writer.flush().await?;

    // PET commit
    let mut buffer = String::new();
    reader.read_line(&mut buffer).await?;
    let pet_data = if let Ok(ControlMessage::PetCommit) = serde_json::from_str(&buffer) {
        println!("PET commit");
        let pet_instances = trustee.validate_votes().await?;
        trustee.do_pet_commits(pet_instances).await?
    } else {
        panic!("unexpected message from leader");
    };

    writer.write_all(&with_newline(ControlMessage::Ok)).await?;
    writer.flush().await?;

    // PET openings
    let mut buffer = String::new();
    reader.read_line(&mut buffer).await?;
    let data = if let Ok(ControlMessage::PetOpenCommits) = serde_json::from_str(&buffer) {
        println!("PET openings");
        trustee.do_pet_openings(pet_data).await?
    } else {
        panic!("unexpected message from leader");
    };

    writer.write_all(&with_newline(ControlMessage::Ok)).await?;
    writer.flush().await?;

    // PET decryptions
    let mut buffer = String::new();
    reader.read_line(&mut buffer).await?;
    if let Ok(ControlMessage::PetDecrypt) = serde_json::from_str(&buffer) {
        println!("PET decryptions");
        trustee.do_pet_decryptions(data).await?;
    } else {
        panic!("unexpected message from leader");
    };

    writer.write_all(&with_newline(ControlMessage::Ok)).await?;
    writer.flush().await?;

    // Last shuffle
    let mut buffer = String::new();
    reader.read_line(&mut buffer).await?;
    if let Ok(ControlMessage::LastShuffle) = serde_json::from_str(&buffer) {
        println!("last shuffle");
        trustee.mix_accepted().await?;
    } else {
        panic!("unexpected message from leader");
    };

    writer.write_all(&with_newline(ControlMessage::Ok)).await?;
    writer.flush().await?;

    // Last decryptions
    let mut buffer = String::new();
    reader.read_line(&mut buffer).await?;
    if let Ok(ControlMessage::LastDecrypt) = serde_json::from_str(&buffer) {
        println!("last decryptions");
        trustee.decrypt_accepted().await?;
    } else {
        panic!("unexpected message from leader");
    };

    writer.write_all(&with_newline(ControlMessage::Ok)).await?;
    writer.flush().await?;

    Ok(())
}
