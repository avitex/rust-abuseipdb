use std::env;
use abuseipdb::Client;

#[tokio::main]
async fn main() {
    let api_key = env::var("API_KEY").unwrap();
    let client = Client::new(api_key);
    let response = client.check_block("127.0.0.1/24", None).await.unwrap();
    println!("{:?}", response);
}
