use std::thread;

use cryptid::elgamal::CryptoContext;
use papervote::trustee;
use papervote::wbb::Api;
use tokio::task;
use uuid::Uuid;

#[tokio::main]
async fn main() {
    let session_id = Uuid::new_v4();
    let ctx = CryptoContext::new();

    let min_trustees = 3;
    let num_trustees = 5;

    let api = Api::new(num_trustees, &ctx).unwrap();
    thread::spawn(move || api.start());

    let mut futures = Vec::new();
    for index in 1..num_trustees + 1 {
        let session_id = session_id.clone();
        let ctx = ctx.cloned();
        futures.push(task::spawn(trustee::run(session_id, ctx, index, min_trustees, num_trustees)));
    }

    for future in futures {
        future.await.unwrap().unwrap();
    }
}
