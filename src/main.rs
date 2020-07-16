#![feature(async_closure)]

use std::thread;

use cryptid::elgamal::CryptoContext;
use eyre::Result;
use papervote::trustee;
use papervote::wbb::Api;
use tokio::task;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    let session_id = Uuid::new_v4();
    let ctx = CryptoContext::new();

    let min_trustees = 6;
    let num_trustees = 9;

    let api = Api::new(num_trustees, &ctx).unwrap();
    thread::spawn(move || api.start());

    let mut futures = Vec::new();
    for index in 1..num_trustees + 1 {
        let session_id = session_id.clone();
        let ctx = ctx.cloned();
        futures.push(task::spawn(trustee::generate(session_id, ctx, index, min_trustees, num_trustees)));
    }

    let trustees: Vec<_> = futures.into_iter()
        .map(async move |future| future.await?)
        .collect();

    for trustee in trustees {
        trustee.await?;
    }

    Ok(())
}
