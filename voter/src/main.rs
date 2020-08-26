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
use common::voter::{Vote, Candidate, Ballot};
use tokio::time;
use tokio::time::Duration;
use std::io::{Write, BufWriter};
use qrcode::QrCode;
use printpdf::{PdfDocument, Mm, Image};
use std::fs::File;
use std::collections::{HashSet, HashMap};


#[tokio::main]
async fn main() -> Result<()> {
    const DELAY: u64 = 1000;
    let cfg: PapervoteConfig = confy::load(APP_NAME)?;
    let candidates = common::voter::candidates_from_file(&cfg.candidate_file)?;
    let ctx = CryptoContext::new()?;
    let commit_ctx = PedersenCtx::new(cfg.session_id.as_bytes());

    // Pull down trustee info
    let client = reqwest::Client::new();
    let mut trustees = None;
    loop {
        if let Ok(val) = get_trustee_info(&cfg, &client).await {
            trustees.replace(val);
            break;
        }
        println!("retrying trustee download...");
        time::delay_for(Duration::from_millis(DELAY)).await;
    }
    let trustees = trustees.unwrap();
    println!("Downloaded trustee information.");

    // Fetch the public key
    let mut pubkey = None;
    loop {
        if let Ok(val) = get_pubkey(&cfg, &trustees, &client).await {
            pubkey.replace(val);
            break;
        }
        println!("retrying public key download...");
        time::delay_for(Duration::from_millis(DELAY)).await;
    }
    let pubkey = pubkey.unwrap();
    println!("Public key: {}", pubkey.as_base64());

    // Create an ID
    let id = base64::encode(Uuid::new_v4().as_bytes()).replace("/", "-");
    let mut voter = Voter::new(cfg.session_id.clone(), pubkey, ctx.clone(), commit_ctx, id)?;

    // Get preferences
    println!("Candidates are:");
    for candidate in candidates.values() {
        println!("\t{}", candidate.name())
    }

    println!("Enter your preferences (1--{}); 1 is your highest preference.", candidates.len());
    let vote = get_vote(candidates)?;
    let vote_str = vote.pretty();
    voter.set_vote(vote);

    // Submit the vote
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
    while let Err(_) = voter.post_vote(&trustees[0].address).await{
        println!("{}: retrying vote", voter.id());
        time::delay_for(Duration::from_millis(DELAY)).await;
    }

    // Produce ballot information
    let ballot = voter.get_ballot()?;

    println!("---");
    println!("Your vote (Paper 1):");
    println!("{}", vote_str);
    println!("Your identification (save this for verification later) (Paper 2):");
    println!("\tID:        {}", ballot.p2_id);
    save_ballots(ballot, vote_str)?;

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

fn get_vote(candidates: HashMap<u64, Candidate>) -> Result<Vote> {
    let mut used_prefs = HashSet::new();
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
                    if !used_prefs.contains(&num) {
                        used_prefs.insert(num);
                        vote.set(candidate, num - 1);
                        break;
                    } else {
                        println!("Already specified preference #{}. (Press Ctrl+C to exit and retry.)", num);
                    }
                } else {
                    println!("Please enter a number between 1 and {}.", candidates.len());
                }
            } else {
                println!("Please enter a number between 1 and {}.", candidates.len());
            }
        }
    }

    Ok(vote)
}

fn save_ballots(ballot: Ballot, vote_str: String) -> Result<()> {
    let mut data = Vec::new();
    data.extend(ballot.p1_enc_a.to_string().as_bytes());
    data.push(b'-');
    data.extend(ballot.p1_enc_b.to_string().as_bytes());
    data.push(b'-');
    data.extend(ballot.p1_enc_r_a.to_string().as_bytes());
    data.push(b'-');
    data.extend(ballot.p1_enc_r_b.to_string().as_bytes());
    data.push(b'-');
    data.extend(ballot.p1_prf_a.to_string().as_bytes());
    data.push(b'-');
    data.extend(ballot.p1_prf_b.to_string().as_bytes());
    data.push(b'-');
    data.extend(ballot.p1_prf_r_a.to_string().as_bytes());
    data.push(b'-');
    data.extend(ballot.p1_prf_r_b.to_string().as_bytes());
    let image = QrCode::new(&data)?.render::<image::Luma<u8>>().build();
    image.save("paper1-img.bmp")?;

    let mut data = Vec::new();
    data.extend(ballot.p2_enc_id.to_string().as_bytes());
    data.push(b'-');
    data.extend(ballot.p2_prf_enc.as_base64().as_bytes());

    let image = QrCode::new(&data)?.render::<image::Luma<u8>>().build();
    image.save("paper2-img.bmp")?;

    // Create PDFs
    let (doc, page1, layer1) = PdfDocument::new("Vote Paper 1", Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page1).get_layer(layer1);

    let font = doc.add_builtin_font(printpdf::BuiltinFont::Courier)?;
    let vote_str = vote_str.replace("\n", " ");
    current_layer.use_text(&format!("Paper 1: {}", vote_str), 14, Mm(25.0), Mm(270.0), &font);

    let mut image_file = File::open("paper1-img.bmp")?;
    let image = Image::try_from(image::bmp::BmpDecoder::new(&mut image_file)?)?;
    image.add_to_layer(current_layer.clone(), Some(Mm(25.0)), Some(Mm(150.0)), None, None, None, None);

    doc.save(&mut BufWriter::new(File::create("paper1.pdf")?))?;

    let (doc, page1, layer1) = PdfDocument::new("Vote Paper 2", Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page1).get_layer(layer1);

    let font = doc.add_builtin_font(printpdf::BuiltinFont::Courier)?;
    current_layer.use_text(&format!("Paper 2: {}", ballot.p2_id.to_string()), 14, Mm(25.0), Mm(270.0), &font);

    let mut image_file = File::open("paper2-img.bmp")?;
    let image = Image::try_from(image::bmp::BmpDecoder::new(&mut image_file)?)?;
    image.add_to_layer(current_layer.clone(), Some(Mm(25.0)), Some(Mm(220.0)), None, None, None, None);

    doc.save(&mut BufWriter::new(File::create("paper2.pdf")?))?;

    std::fs::remove_file("paper1-img.bmp")?;
    std::fs::remove_file("paper2-img.bmp")?;

    println!("Files to print saved to `paper1.pdf` and `paper2.pdf`.");

    Ok(())
}