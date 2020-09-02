use eyre::Result;
use cryptid::elgamal::Ciphertext;
use std::convert::TryFrom;
use common::voter::{VoterMessage, Ballot};
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use cryptid::zkp::PrfKnowPlaintext;

pub async fn run_receive(address: &str) -> Result<()> {
    let stdin = std::io::stdin();

    let mut input = String::new();
    println!("Enter vote:");
    stdin.read_line(&mut input)?;
    let vote = input.trim().to_string();

    let mut input = String::new();
    println!("Paper 2 encryption:");
    stdin.read_line(&mut input)?;
    let mut parts = input.split('-');
    let ct_str = parts.next()
        .expect("Malformed encryption (missing part 1)")
        .trim();
    let _p2_prf_enc = parts.next()
        .expect("Malformed encryption (missing part 2)")
        .trim();
    let p2_enc_id = Ciphertext::try_from(ct_str)?;

    // TODO: Check proof of encryption

    let mut input = String::new();
    println!("Paper 1, encryption 1:");
    stdin.read_line(&mut input)?;
    let mut parts = input.trim().split('-');
    let enc_a = parts.next()
        .expect("Malformed encryption (missing part 1)")
        .trim();
    let enc_b = parts.next()
        .expect("Malformed encryption (missing part 2)")
        .trim();

    let mut input = String::new();
    println!("Paper 1, encryption 2:");
    stdin.read_line(&mut input)?;
    let mut parts = input.trim().split('-');
    let enc_r_a = parts.next()
        .expect("Malformed encryption (missing part 1)")
        .trim();
    let enc_r_b = parts.next()
        .expect("Malformed encryption (missing part 2)")
        .trim();

    let mut input = String::new();
    println!("Paper 1, proof 1:");
    stdin.read_line(&mut input)?;
    let mut parts = input.trim().split('_');
    let prf_a = parts.next()
        .expect("Malformed proof (missing part 1)")
        .trim();
    let prf_b = parts.next()
        .expect("Malformed proof (missing part 2)")
        .trim();

    let mut input = String::new();
    println!("Paper 1, proof 2:");
    stdin.read_line(&mut input)?;
    let mut parts = input.trim().split('_');
    let prf_r_a = parts.next()
        .expect("Malformed proof (missing part 1)")
        .trim();
    let prf_r_b = parts.next()
        .expect("Malformed proof (missing part 1)")
        .trim();

    let enc_a = Ciphertext::try_from(enc_a)
        .expect("Malformed encryption (encryption 1, part 1)");
    let enc_b = Ciphertext::try_from(enc_b)
        .expect("Malformed encryption (encryption 1, part 2)");
    let enc_r_a = Ciphertext::try_from(enc_r_a)
        .expect("Malformed encryption (encryption 2, part 1)");
    let enc_r_b = Ciphertext::try_from(enc_r_b)
        .expect("Malformed encryption (encryption 2, part 2)");

    println!("Ciphertexts decoded.");

    let prf_a = PrfKnowPlaintext::try_from(prf_a)
        .expect("Malformed proof (proof 1, part 1)");
    let prf_b = PrfKnowPlaintext::try_from(prf_b)
        .expect("Malformed proof (proof 1, part 2)");
    let prf_r_a = PrfKnowPlaintext::try_from(prf_r_a)
        .expect("Malformed proof (proof 2, part 1)");
    let prf_r_b = PrfKnowPlaintext::try_from(prf_r_b)
        .expect("Malformed proof (proof 2, part 1)");

    println!("Proofs decoded.");

    if prf_a.verify() && prf_b.verify() && prf_r_a.verify() && prf_r_b.verify() {
        println!("Proofs valid.");
    } else {
        println!("Proofs invalid, rejecting ballot.");
    }
    
    let ballot = Ballot {
        p1_vote: vote,
        p1_enc_a: enc_a,
        p1_enc_b: enc_b,
        p1_enc_r_a: enc_r_a,
        p1_enc_r_b: enc_r_b,
        p1_prf_a: prf_a,
        p1_prf_b: prf_b,
        p1_prf_r_a: prf_r_a,
        p1_prf_r_b: prf_r_b,
        p2_enc_id,
    };

    let msg = VoterMessage::Ballot(ballot);
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(serde_json::to_string(&msg)?
        .as_ref()).await?;
    println!("Vote received.");

    Ok(())
}
