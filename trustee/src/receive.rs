use eyre::Result;
use cryptid::elgamal::Ciphertext;
use std::convert::TryFrom;
use cryptid::{Scalar, AsBase64};
use common::voter::{VoterMessage, Ballot, VoterId};
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use cryptid::zkp::PrfKnowPlaintext;

pub async fn run_receive(address: &str) -> Result<()> {
    let stdin = std::io::stdin();

    let mut input = String::new();
    println!("Enter voter ID:");
    stdin.read_line(&mut input)?;
    let voter_id = VoterId::from(input.trim().to_string());

    let mut input = String::new();
    println!("Enter vote:");
    stdin.read_line(&mut input)?;
    let vote = input.trim().to_string();

    let mut input = String::new();
    println!("Enter Paper 2 data:");
    stdin.read_line(&mut input)?;
    let mut parts = input.split('-');
    let ct_str = parts.next().unwrap().trim();
    let scalar_str = parts.next().unwrap().trim();
    let p2_enc_id = Ciphertext::try_from(ct_str)?;
    let p2_prf_enc = Scalar::try_from_base64(scalar_str)?;

    let mut input = String::new();
    println!("Enter Paper 1 data:");
    stdin.read_line(&mut input)?;

    let mut parts = input.trim().split('-');
    let enc_a = parts.next().unwrap().trim();
    let enc_b = parts.next().unwrap().trim();
    let enc_r_a = parts.next().unwrap().trim();
    let enc_r_b = parts.next().unwrap().trim();
    let prf_a = parts.next().unwrap().trim();
    let prf_b = parts.next().unwrap().trim();
    let prf_r_a = parts.next().unwrap().trim();
    let prf_r_b = parts.next().unwrap().trim();

    let enc_a = Ciphertext::try_from(enc_a)?;
    let enc_b = Ciphertext::try_from(enc_b)?;
    let enc_r_a = Ciphertext::try_from(enc_r_a)?;
    let enc_r_b = Ciphertext::try_from(enc_r_b)?;
    println!("Ciphertexts decoded.");

    // let prf_a = PrfKnowPlaintext::try_from(prf_a)?;
    // let prf_b = PrfKnowPlaintext::try_from(prf_b)?;
    // let prf_r_a = PrfKnowPlaintext::try_from(prf_r_a)?;
    // let prf_r_b = PrfKnowPlaintext::try_from(prf_r_b)?;

    // if prf_a.verify() && prf_b.verify() && prf_r_a.verify() && prf_r_b.verify() {
    //     println!("Proofs validated.");
    // } else {
    //     println!("Proofs invalid, rejecting ballot.");
    // }
    
    let ballot = Ballot {
        p1_vote: vote,
        p1_enc_a: enc_a,
        p1_enc_b: enc_b,
        p1_enc_r_a: enc_r_a,
        p1_enc_r_b: enc_r_b,
        // p1_prf_a: prf_a,
        // p1_prf_b: prf_b,
        // p1_prf_r_a: prf_r_a,
        // p1_prf_r_b: prf_r_b,
        p2_id: voter_id,
        p2_enc_id,
        p2_prf_enc,
    };

    let msg = VoterMessage::Ballot(ballot);
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(serde_json::to_string(&msg)?
        .as_ref()).await?;
    println!("Vote received.");

    Ok(())
}
