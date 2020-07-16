use uuid::Uuid;
use cryptid::elgamal::CryptoContext;
use papervote::trustee::{GeneratingTrustee, TrusteeMessage, TrusteeError};
use papervote::wbb::{Api, WrappedResponse, Response};
use tokio::{task, time};
use eyre::Result;
use std::thread;
use tokio::time::Duration;
use reqwest::Client;

fn address(session_id: &Uuid, path: &str) -> String {
    format!("http://localhost:8000/api/{}{}", session_id, path)
}

#[tokio::main]
async fn main() {
    let session_id = Uuid::new_v4();
    let ctx = CryptoContext::new();

    let min_trustees = 1;
    let num_trustees = 3;

    let api = Api::new(num_trustees, &ctx).unwrap();
    thread::spawn(move || api.start());

    let mut futures = Vec::new();
    for index in 1..num_trustees + 1 {
        let session_id = session_id.clone();
        let ctx = ctx.cloned();
        futures.push(task::spawn(run_trustee(session_id, ctx, index, min_trustees, num_trustees)));
    }

    for future in futures {
        future.await.unwrap().unwrap();
    }
}

async fn run_trustee(session_id: Uuid,
                     ctx: CryptoContext,
                     index: usize,
                     min_trustees: usize,
                     num_trustees: usize) -> Result<()> {
    let mut trustee = GeneratingTrustee::new(session_id.clone(), &ctx, index, min_trustees, num_trustees)?;
    let client = reqwest::Client::new();

    // 1. Registration
    let msg = trustee.gen_registration();
    let _receipt: WrappedResponse = client.post(&address(trustee.session_id(), "/trustee/register"))
        .json(&msg).send().await?
        .json().await?;
    // TODO: Check receipt signature, store in database
    get_registrations(&client, &mut trustee).await?;
    assert!(trustee.received_info());

    // 2. Commitment
    let msg = trustee.gen_commitment();
    let _receipt: WrappedResponse = client.post(&address(trustee.session_id(), "/keygen/commitment"))
        .json(&msg).send().await?
        .json().await?;
    // TODO: Check receipt signature, store in database
    get_commitments(&client, &mut trustee).await?;
    assert!(trustee.received_commitments());

    // 3. Shares
    // TODO: Trustees need to communicate directly with each other here.
    let _shares = trustee.gen_shares()?;

    Ok(())
}

async fn get_registrations(client: &Client, trustee: &mut GeneratingTrustee) -> Result<()> {
    loop {
        // Wait a moment for other registrations
        time::delay_for(Duration::from_millis(200)).await;
        let res: WrappedResponse = client.get(&address(trustee.session_id(), "/trustee/all"))
            .send().await?
            .json().await?;

        // Check signatures
        if let Response::ResultSet(results) = res.msg {
            for result in results {
                if let TrusteeMessage::Info { info } = &result.inner {
                    if result.verify(&info.pubkey)? {
                        trustee.add_info(info.clone());
                    }
                }
            }
            break;
        }
    }

    Ok(())
}

async fn get_commitments(client: &Client, trustee: &mut GeneratingTrustee) -> Result<()> {
    loop {
        // Wait a moment for other registrations
        time::delay_for(Duration::from_millis(200)).await;
        let res: WrappedResponse = client.get(&address(trustee.session_id(), "/keygen/commitment"))
            .send().await?
            .json().await?;

        // Check signatures
        if let Response::ResultSet(results) = res.msg {
            if trustee.verify_all(&results)? {
                for result in results {
                    if let TrusteeMessage::KeygenCommit { commitment } = result.inner {
                        trustee.add_commitment(&result.sender_id, &commitment)?;
                    } else {
                        return Err(TrusteeError::InvalidResponse)?;
                    }
                }
                return Ok(());
            } else {
                return Err(TrusteeError::InvalidSignature)?;
            }
        }
    }
}