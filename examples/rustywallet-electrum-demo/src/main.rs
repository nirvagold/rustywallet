//! Demo for rustywallet-electrum crate v0.2
//!
//! Tests connection to Electrum server, balance checking, and new v0.2 features.

use rustywallet_electrum::{
    ElectrumClient, ClientConfig,
    discovery::ServerDiscovery,
    pool::PoolConfig,
    batch::BatchRequest,
    pinning::{CertFingerprint, CertPinStore},
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== rustywallet-electrum v0.2 Demo ===\n");

    // ========== 1. Server Discovery ==========
    println!("1. Server Discovery...");
    let discovery = ServerDiscovery::new();
    let servers = discovery.discover();
    println!("   Found {} DNS seeds", servers.len());
    for server in servers.iter().take(3) {
        println!("   - {} (SSL: {}, TCP: {})", 
            server.hostname, server.ssl_port, server.tcp_port);
    }
    println!();

    // ========== 2. Connect to Server ==========
    println!("2. Connecting to Electrum server...");
    let servers_to_try = [
        ("electrum.blockstream.info", 50002, true, false),
        ("electrum1.bluewallet.io", 443, true, true),
        ("bitcoin.aranguren.org", 50002, true, true),
    ];

    let mut client = None;
    for (server, port, use_tls, skip_verify) in servers_to_try {
        println!("   Trying {}:{}...", server, port);
        
        let mut config = if use_tls {
            ClientConfig::ssl(server).with_port(port)
        } else {
            ClientConfig::tcp(server).with_port(port)
        }.with_timeout(Duration::from_secs(15));
        
        if skip_verify {
            config = config.with_skip_tls_verify();
        }
        
        match ElectrumClient::with_config(config).await {
            Ok(c) => {
                println!("   ✓ Connected to {}!\n", server);
                client = Some(c);
                break;
            }
            Err(e) => {
                println!("   ✗ Failed: {}", e);
            }
        }
    }

    let client = client.ok_or("Failed to connect to any server")?;

    // ========== 3. Server Info ==========
    println!("3. Getting server info...");
    let version = client.server_version().await?;
    println!("   Server: {}", version.server_software);
    println!("   Protocol: {}", version.protocol_version);
    
    let height = client.get_block_height().await?;
    println!("   Block height: {}\n", height);

    // ========== 4. Certificate Pinning Demo ==========
    println!("4. Certificate Pinning (demo)...");
    let mut pin_store = CertPinStore::new();
    let dummy_fp = CertFingerprint::from_bytes([0u8; 32]);
    pin_store.add_pin("example.com", dummy_fp.clone());
    println!("   Created pin store with {} server(s)", pin_store.server_count());
    println!("   Fingerprint format: {}\n", dummy_fp.to_hex()[..32].to_string() + "...");

    // ========== 5. Batch Request ==========
    println!("5. Batch Request...");
    let addresses = [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  // Satoshi genesis
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",  // P2SH example
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", // P2WPKH example
    ];
    
    match BatchRequest::new(&client)
        .balances(addresses.iter().map(|s| s.to_string()))
        .execute()
        .await
    {
        Ok(response) => {
            println!("   Total confirmed: {} sats", response.total_confirmed());
            println!("   Funded addresses: {}", response.funded_addresses().len());
            for addr in addresses.iter() {
                if let Some(bal) = response.get_balance(addr) {
                    let btc = bal.confirmed as f64 / 100_000_000.0;
                    println!("   - {}... = {:.8} BTC", &addr[..16], btc);
                }
            }
        }
        Err(e) => {
            println!("   ⚠ Error: {}", e);
        }
    }
    println!();

    // ========== 6. Connection Pool Demo ==========
    println!("6. Connection Pool (demo)...");
    let pool_config = PoolConfig::default()
        .min_connections(1)
        .max_connections(5)
        .idle_timeout(Duration::from_secs(60));
    println!("   Pool config: min={}, max={}", 
        pool_config.min_connections, pool_config.max_connections);
    
    // Note: We can't actually test the pool without a new connection
    // Just demonstrate the API
    println!("   Pool API available: ConnectionPool::new(), acquire(), stats()\n");

    // ========== 7. Single Balance Check ==========
    println!("7. Single balance check...");
    let satoshi_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    match client.get_balance(satoshi_addr).await {
        Ok(balance) => {
            println!("   Address: {}", satoshi_addr);
            println!("   Confirmed: {} sats ({:.8} BTC)", 
                balance.confirmed, balance.confirmed as f64 / 100_000_000.0);
            println!("   Unconfirmed: {} sats", balance.unconfirmed);
            println!("   Has balance: {}", balance.has_balance());
        }
        Err(e) => {
            println!("   ⚠ Error: {}", e);
        }
    }
    println!();

    // ========== 8. UTXO Listing ==========
    println!("8. UTXO listing...");
    match client.list_unspent(satoshi_addr).await {
        Ok(utxos) => {
            println!("   Found {} UTXOs", utxos.len());
            for utxo in utxos.iter().take(3) {
                println!("   - {}:{} = {} sats (height: {})", 
                    &utxo.txid[..16], utxo.vout, utxo.value, utxo.height);
            }
        }
        Err(e) => {
            println!("   ⚠ Error: {}", e);
        }
    }
    println!();

    // ========== 9. Transaction History ==========
    println!("9. Transaction history...");
    match client.get_history(satoshi_addr).await {
        Ok(history) => {
            println!("   Found {} transactions", history.len());
            for tx in history.iter().rev().take(3) {
                let status = if tx.is_confirmed() { 
                    format!("height {}", tx.height) 
                } else { 
                    "unconfirmed".to_string() 
                };
                println!("   - {}... ({})", &tx.txid[..16], status);
            }
        }
        Err(e) => {
            println!("   ⚠ Error: {}", e);
        }
    }
    println!();

    // ========== 10. Fee Estimation ==========
    println!("10. Fee estimation...");
    match client.estimate_fee(6).await {
        Ok(fee) => {
            println!("   6 blocks: {:.8} BTC/kB ({:.0} sat/vB)", fee, fee * 100_000.0);
        }
        Err(e) => {
            println!("   ⚠ Error: {}", e);
        }
    }
    println!();

    // ========== 11. Subscription API Demo ==========
    println!("11. Subscription API (demo)...");
    println!("   Available: SubscriptionClient, AddressWatcher");
    println!("   Events: AddressStatus, BlockHeader, ConnectionStatus");
    println!("   Methods: subscribe_address(), subscribe_headers(), subscribe()\n");

    println!("=== Demo Complete! ===");
    println!("\nv0.2 Features demonstrated:");
    println!("  ✓ Server Discovery (DNS seeds)");
    println!("  ✓ Certificate Pinning API");
    println!("  ✓ Batch Request Builder");
    println!("  ✓ Connection Pool Config");
    println!("  ✓ Subscription API");
    
    Ok(())
}
