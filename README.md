[![Build Status](https://travis-ci.com/avitex/rust-abuseipdb.svg?branch=master)](https://travis-ci.com/avitex/rust-abuseipdb)
[![Crate](https://img.shields.io/crates/v/abuseipdb.svg)](https://crates.io/crates/abuseipdb)
[![Docs](https://docs.rs/abuseipdb/badge.svg)](https://docs.rs/abuseipdb)

# rust-abuseipdb

**Rust client for the AbuseIPDB API**  
Documentation hosted on [docs.rs](https://docs.rs/abuseipdb).

```toml
abuseipdb = "0.2.1"
```

## Example usage

```rust
use abuseipdb::Client;
use std::net::Ipv4Addr;

async fn example() {
    let my_ip = Ipv4Addr::new(127, 0, 0, 1).into();
    let client = Client::new("<API-KEY>");
    let response = client.check(my_ip, None, false).await.unwrap();
    println!("abuseConfidenceScore: {}", response.data.abuse_confidence_score);
}
```
