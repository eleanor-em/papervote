use wbb::api::Api;

use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let api = Api::new().await?;
    api.start();

    Ok(())
}
