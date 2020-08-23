use common::config::PapervoteConfig;
use common::net::{Response, TrusteeMessage};
use common::APP_NAME;
use cryptid::elgamal::{CryptoContext, PublicKey};
use cryptid::commit::PedersenCtx;
use uuid::Uuid;
use voter::{Voter, VoterError};
use common::net::{WrappedResponse, TrusteeInfo};
use eyre::Result;
use reqwest::Client;
use cryptid::AsBase64;
use common::voter::Vote;
use tokio::time;
use tokio::time::Duration;
use std::io::Write;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg: PapervoteConfig = confy::load(APP_NAME)?;
    let candidates = common::voter::candidates_from_file(&cfg.candidate_file)?;
    let ctx = CryptoContext::new()?;
    let commit_ctx = PedersenCtx::new(cfg.session_id.as_bytes());

    // Pull down trustee info
    let client = reqwest::Client::new();
    let trustees = get_trustee_info(&cfg, &client).await?;
    println!("Downloaded trustee information.");

    // Fetch the public key
    let pubkey = get_pubkey(&cfg, &trustees, &client).await?;
    println!("Public key: {}", pubkey.as_base64());

    let id = base64::encode(Uuid::new_v4().as_bytes()).replace("/", "-");
    let mut voter = Voter::new(cfg.session_id.clone(), pubkey, ctx.clone(), commit_ctx, id)?;

    println!("Candidates are:");
    for candidate in candidates.values() {
        println!("\t{}", candidate.name())
    }

    println!("Enter your preferences (1--{}).", candidates.len());
    let mut vote = Vote::new();
    for candidate in candidates.values() {
        loop {
            // Get voter preference
            print!("{}: ", candidate.name());
            std::io::stdout().flush()?;
            
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            input = input.trim().to_string();
            if let Ok(num) = input.parse::<u64>() {
                if num >= 1 && num <= candidates.len() as u64 {
                    vote.set(candidate, num - 1);
                    break;
                } else {
                    println!("Please enter a number between 1 and {}.", candidates.len());
                }
            } else {
                println!("Please enter a number between 1 and {}.", candidates.len());
            }
        }
    }

    let vote_str = vote.pretty();
    voter.set_vote(vote);

    // Submit the vote
    const DELAY: u64 = 1000;

    while let Err(_) = voter.post_init_commit(&cfg.api_url).await {
        println!("retrying ident message");
        time::delay_for(Duration::from_millis(DELAY)).await;
    }

    loop {
        if let Ok(()) = voter.post_ec_commit(&trustees[0].address).await {
            if let Ok(()) = voter.check_ec_commit(&cfg.api_url).await {
                break;
            }
        }
        println!("retrying commit message...");
        time::delay_for(Duration::from_millis(DELAY)).await;
    }

    // for debugging
    // while let Err(_) = voter.post_vote(&trustees[0].address).await{
    //     println!("{}: retrying vote", voter.id());
    //     time::delay_for(Duration::from_millis(DELAY)).await;
    // }

    let ballot = voter.get_ballot()?;

    println!("---");
    println!("Your vote (Paper 1):");
    println!("{}", vote_str);
    println!("Your encrypted parameters (Paper 1):");
    println!("\ta:   {}", ballot.p1_enc_a.to_string());
    println!("\tb:   {}", ballot.p1_enc_b.to_string());
    println!("\tr_a: {}", ballot.p1_enc_r_a.to_string());
    println!("\tr_b: {}", ballot.p1_enc_r_b.to_string());
    println!("\tproof a:   {}", ballot.p1_prf_a.to_string());
    println!("\tproof b:   {}", ballot.p1_prf_b.to_string());
    println!("\tproof r_a: {}", ballot.p1_prf_r_a.to_string());
    println!("\tproof r_b: {}", ballot.p1_prf_r_b.to_string());
    println!("---");
    println!("Your identification (Paper 2):");
    println!("\tID: {}", ballot.p2_id);
    println!("\t    {}", ballot.p2_enc_id.to_string());
    println!("\t    {}", ballot.p2_prf_enc.as_base64());

    Ok(())
}

async fn get_trustee_info(cfg: &PapervoteConfig, client: &Client) -> Result<Vec<TrusteeInfo>> {
    let response: WrappedResponse = client.get(&format!("{}/{}/trustee/all", cfg.api_url, cfg.session_id))
        .send().await?
        .json().await?;

    if !response.status {
        return Err(VoterError::Api(response.msg))?;
    }

    if let Response::ResultSet(messages) = response.msg {
        let mut trustees = Vec::new();

        // Extract the info
        for msg in messages {
            if let TrusteeMessage::Info { info } = &msg.inner {
                // Check the signature
                if msg.verify(&info.pubkey)? {
                    trustees.push(info.clone());
                } else {
                    eprintln!("Failed verifying trustee signature: {}", info.id);
                    return Err(VoterError::Decode)?;
                }
            } else {
                eprintln!("Failed decoding trustee info message.");
                return Err(VoterError::Decode)?;
            }
        }

        Ok(trustees)
    } else {
        eprintln!("Failed decoding WBB response.");
        return Err(VoterError::Decode)?;
    }
}

async fn get_pubkey(cfg: &PapervoteConfig, trustees: &[TrusteeInfo], client: &Client) -> Result<PublicKey> {
    let response: WrappedResponse = client.get(&format!("{}/{}/keygen/sign/all", cfg.api_url, cfg.session_id))
        .send().await?
        .json().await?;

    if !response.status {
        return Err(VoterError::Api(response.msg))?;
    }

    if let Response::ResultSet(messages) = response.msg {
        let mut pubkey = None;

        // Extract the info
        for msg in messages {
            if let TrusteeMessage::KeygenSign { pubkey: msg_pubkey, pubkey_proof: _ } = &msg.inner {
                let mut verified = false;
                // Look up correct signing public key
                for trustee in trustees {
                    if trustee.id == msg.sender_id {
                        // Check the signature
                        if msg.verify(&trustee.pubkey)? {
                            verified = true;
                            match pubkey {
                                None => {
                                    pubkey = Some(msg_pubkey.clone());
                                    break;
                                },
                                Some(existing) => {
                                    if existing != *msg_pubkey {
                                        eprintln!("Trustees committed to inconsistent public keys.");
                                        return Err(VoterError::Decode)?;
                                    }
                                }
                            }
                        } else {
                            eprintln!("Failed verifying trustee signature: {}", trustee.id);
                            return Err(VoterError::Decode)?;
                        }
                    }
                }

                if !verified {
                    eprintln!("Unrecognised trustee: {}", msg.sender_id);
                    return Err(VoterError::Decode)?;
                }
            } else {
                eprintln!("Failed decoding pubkey message.");
                return Err(VoterError::Decode)?;
            }
        }

        Ok(pubkey.unwrap())
    } else {
        eprintln!("Failed decoding WBB response.");
        return Err(VoterError::Decode)?;
    }
}