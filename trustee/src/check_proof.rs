use eyre::Result;
use common::voter::VoterId;
use cryptid::elgamal::{Ciphertext, CryptoContext, PublicKey, CurveElem};
use std::convert::TryFrom;
use cryptid::{Scalar, AsBase64};

pub fn run_check_proof() -> Result<()> {
    let ctx = CryptoContext::new()?;
    let stdin = std::io::stdin();

    // Jp9ipOXfzsDj8OQMU6DC2y+RGMbsk+rNHGN2rXSvKgY=
    let mut input = String::new();
    println!("Enter public key:");
    stdin.read_line(&mut input)?;
    let pubkey = PublicKey::new(CurveElem::try_from_base64(input.trim())?);

    let mut input = String::new();
    println!("Enter voter ID:");
    stdin.read_line(&mut input)?;
    let voter_id = VoterId::from(input.trim().to_string());

    let mut input = String::new();
    println!("Enter scanned encryption:");
    stdin.read_line(&mut input)?;
    let mut parts = input.split('-');

    let ct_str = parts.next().unwrap().trim();
    let scalar_str = parts.next().unwrap().trim();
    println!("\t{}", ct_str);
    println!("\t{}", scalar_str);

    let ct = Ciphertext::try_from(ct_str)?;
    let scalar = Scalar::try_from_base64(scalar_str)?;

    println!("Loaded data.");
    if pubkey.encrypt(&ctx, &voter_id.try_as_curve_elem().unwrap(), &scalar) == ct {
        println!("OK.");
    } else {
        println!("Failed proof verification.");
    }

    Ok(())
}