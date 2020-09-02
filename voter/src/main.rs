use common::config::PapervoteConfig;
use common::APP_NAME;
use cryptid::elgamal::CryptoContext;
use cryptid::commit::PedersenCtx;
use uuid::Uuid;
use voter::{Voter, get_trustee_info, get_pubkey};
use eyre::Result;
use cryptid::{AsBase64, Scalar};
use common::voter::{Vote, Candidate, Ballot};
use tokio::time;
use tokio::time::Duration;
use std::io::{Write, BufWriter};
use qrcode::{QrCode, EcLevel};
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
    let mut trustees = trustees.unwrap();
    println!("Downloaded trustee information.");

    // Fetch the public key
    let mut pubkey = None;
    loop {
        if let Ok(val) = get_pubkey(&cfg, &mut trustees, &client).await {
            pubkey.replace(val);
            break;
        }
        println!("retrying public key download...");
        time::delay_for(Duration::from_millis(DELAY)).await;
    }
    let pubkey = pubkey.unwrap();
    println!("Public key: {}", pubkey.as_base64());

    // Create an ID; just use random bytes for the prototype
    let mut voter_id_str = Uuid::new_v4().to_string()
        .replace("-", "");
    voter_id_str.truncate(10);
    let mut voter = Voter::new(cfg.session_id.clone(), pubkey, ctx.clone(), commit_ctx, voter_id_str.clone())?;

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

    // Produce ballot information
    let (ballot, prf_enc_id) = voter.get_ballot()?;

    println!("---");
    println!("Your vote (Paper 1):");
    println!("{}", vote_str);
    println!("Your identification (save this for verification later) (Paper 2):");
    println!("\tID: {}", voter_id_str);
    save_ballots(&cfg, ballot, prf_enc_id, voter_id_str, vote_str)?;

    Ok(())
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

fn save_ballots(cfg: &PapervoteConfig, ballot: Ballot, prf_enc_id: Scalar, voter_id_str: String, vote_str: String) -> Result<()> {
    let ec_level = EcLevel::Q;

    // Save a copy of the raw data as well in debug mode
    let mut raw_data = Vec::new();
    
    let mut data = Vec::new();
    data.extend(ballot.p1_enc_a.to_string().as_bytes());
    data.push(b'-');
    data.extend(ballot.p1_enc_b.to_string().as_bytes());
    raw_data.push(data.clone());
    let image = QrCode::with_error_correction_level(&data, ec_level)?.render::<image::Luma<u8>>().build();
    image.save("paper1-enc1-img.bmp")?;

    let mut data = Vec::new();
    data.extend(ballot.p1_enc_r_a.to_string().as_bytes());
    data.push(b'-');
    data.extend(ballot.p1_enc_r_b.to_string().as_bytes());
    raw_data.push(data.clone());
    let image = QrCode::with_error_correction_level(&data, ec_level)?.render::<image::Luma<u8>>().build();
    image.save("paper1-enc2-img.bmp")?;

    let mut data = Vec::new();
    data.extend(ballot.p1_prf_a.to_string().as_bytes());
    data.push(b'_');
    data.extend(ballot.p1_prf_b.to_string().as_bytes());
    raw_data.push(data.clone());
    let image = QrCode::with_error_correction_level(&data, ec_level)?.render::<image::Luma<u8>>().build();
    image.save("paper1-prf1-img.bmp")?;

    let mut data = Vec::new();
    data.extend(ballot.p1_prf_r_a.to_string().as_bytes());
    data.push(b'_');
    data.extend(ballot.p1_prf_r_b.to_string().as_bytes());
    raw_data.push(data.clone());
    let image = QrCode::with_error_correction_level(&data, ec_level)?.render::<image::Luma<u8>>().build();
    image.save("paper1-prf2-img.bmp")?;

    let mut data = Vec::new();
    data.extend(ballot.p2_enc_id.to_string().as_bytes());
    data.push(b'-');
    data.extend(prf_enc_id.as_base64().as_bytes());
    raw_data.push(data.clone());
    let image = QrCode::new(&data)?.render::<image::Luma<u8>>().build();
    image.save("paper2-img.bmp")?;

    // Create PDFs
    let (doc, page1, layer1) = PdfDocument::new("Vote Paper 1", Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page1).get_layer(layer1);

    let font = doc.add_builtin_font(printpdf::BuiltinFont::Courier)?;
    let vote_str = vote_str.replace("\n", "  ");
    current_layer.use_text(&format!("Paper 1 -- Vote: {}", vote_str), 14, Mm(25.0), Mm(270.0), &font);

    current_layer.use_text("Encryptions:", 12, Mm(25.0), Mm(260.0), &font);
    current_layer.use_text("Proofs:", 12, Mm(25.0), Mm(190.0), &font);

    let mut image_file = File::open("paper1-enc1-img.bmp")?;
    let image = Image::try_from(image::bmp::BmpDecoder::new(&mut image_file)?)?;
    image.add_to_layer(current_layer.clone(), Some(Mm(25.0)), Some(Mm(200.0)), None, None, None, None);
    let mut image_file = File::open("paper1-enc2-img.bmp")?;
    let image = Image::try_from(image::bmp::BmpDecoder::new(&mut image_file)?)?;
    image.add_to_layer(current_layer.clone(), Some(Mm(110.0)), Some(Mm(200.0)), None, None, None, None);

    let mut image_file = File::open("paper1-prf1-img.bmp")?;
    let image = Image::try_from(image::bmp::BmpDecoder::new(&mut image_file)?)?;
    image.add_to_layer(current_layer.clone(), Some(Mm(25.0)), Some(Mm(105.0)), None, None, None, None);
    let mut image_file = File::open("paper1-prf2-img.bmp")?;
    let image = Image::try_from(image::bmp::BmpDecoder::new(&mut image_file)?)?;
    image.add_to_layer(current_layer.clone(), Some(Mm(110.0)), Some(Mm(105.0)), None, None, None, None);

    doc.save(&mut BufWriter::new(File::create("paper1.pdf")?))?;

    let (doc, page1, layer1) = PdfDocument::new("Vote Paper 2", Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page1).get_layer(layer1);

    let font = doc.add_builtin_font(printpdf::BuiltinFont::Courier)?;
    current_layer.use_text(&format!("Paper 2 -- VoterID: {}", voter_id_str), 14, Mm(25.0), Mm(270.0), &font);

    let mut image_file = File::open("paper2-img.bmp")?;
    let image = Image::try_from(image::bmp::BmpDecoder::new(&mut image_file)?)?;
    image.add_to_layer(current_layer.clone(), Some(Mm(25.0)), Some(Mm(220.0)), None, None, None, None);

    doc.save(&mut BufWriter::new(File::create("paper2.pdf")?))?;

    std::fs::remove_file("paper1-enc1-img.bmp")?;
    std::fs::remove_file("paper1-enc2-img.bmp")?;
    std::fs::remove_file("paper1-prf1-img.bmp")?;
    std::fs::remove_file("paper1-prf2-img.bmp")?;
    std::fs::remove_file("paper2-img.bmp")?;

    println!("Files to print saved to `paper1.pdf` and `paper2.pdf`.");

    // In debug mode, save raw data
    if cfg.debug_mode {
        let mut raw_text = String::new();
        raw_text += &format!("{}\n", ballot.p1_vote);
        raw_text += &format!("{}\n", std::str::from_utf8(&raw_data[4])?);
        raw_text += &format!("{}\n", std::str::from_utf8(&raw_data[0])?);
        raw_text += &format!("{}\n", std::str::from_utf8(&raw_data[1])?);
        raw_text += &format!("{}\n", std::str::from_utf8(&raw_data[2])?);
        raw_text += &format!("{}\n", std::str::from_utf8(&raw_data[3])?);
        let mut file = std::fs::File::create(std::path::Path::new("raw.txt"))?;
        file.write_all(raw_text.as_ref())?;
    }

    Ok(())
}