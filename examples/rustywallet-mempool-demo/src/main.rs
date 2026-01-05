//! Demo for rustywallet-mempool crate v0.2
//!
//! Tests Mempool.space API client functionality including new v0.2 features.

use rustywallet_mempool::{
    MempoolClient,
    websocket::{MempoolWsClient, WsSubscription},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== rustywallet-mempool v0.2 Demo ===\n");

    let client = MempoolClient::new();

    // 1. Get fee estimates
    println!("1. Getting fee estimates...");
    match client.get_fees().await {
        Ok(fees) => {
            println!("   Next block (fastest): {} sat/vB", fees.fastest_fee);
            println!("   30 minutes: {} sat/vB", fees.half_hour_fee);
            println!("   1 hour: {} sat/vB", fees.hour_fee);
            println!("   Economy (~6h): {} sat/vB", fees.economy_fee);
            println!("   Minimum: {} sat/vB", fees.minimum_fee);
        }
        Err(e) => println!("   ⚠ Error: {}", e),
    }
    println!();

    // 2. Get current block height
    println!("2. Getting block height...");
    match client.get_block_height().await {
        Ok(height) => println!("   Current block: {}", height),
        Err(e) => println!("   ⚠ Error: {}", e),
    }
    println!();

    // 3. Get address info (Satoshi's genesis address)
    println!("3. Getting address info for Satoshi's genesis address...");
    let satoshi_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    match client.get_address(satoshi_addr).await {
        Ok(info) => {
            println!("   Address: {}", info.address);
            println!("   Confirmed balance: {} sats ({:.8} BTC)", 
                info.confirmed_balance(), 
                info.confirmed_balance() as f64 / 100_000_000.0);
            println!("   Unconfirmed: {} sats", info.unconfirmed_balance());
            println!("   Total transactions: {}", info.tx_count());
        }
        Err(e) => println!("   ⚠ Error: {}", e),
    }
    println!();

    // 4. Get UTXOs
    println!("4. Getting UTXOs...");
    match client.get_utxos(satoshi_addr).await {
        Ok(utxos) => {
            println!("   Found {} UTXOs", utxos.len());
            if !utxos.is_empty() {
                println!("   First 3 UTXOs:");
                for utxo in utxos.iter().take(3) {
                    let status = if utxo.is_confirmed() { "confirmed" } else { "unconfirmed" };
                    println!("     - {}:{} = {} sats ({})", 
                        &utxo.txid[..16], utxo.vout, utxo.value, status);
                }
            }
        }
        Err(e) => println!("   ⚠ Error: {}", e),
    }
    println!();

    // ========== v0.2 Features ==========

    // 5. Lightning Network Stats
    println!("5. Getting Lightning Network stats...");
    match client.get_lightning_stats().await {
        Ok(stats) => {
            println!("   Network capacity: {:.2} BTC", stats.latest.capacity_btc());
            println!("   Channels: {}", stats.latest.channel_count);
            println!("   Nodes: {}", stats.latest.node_count);
            println!("   Avg channel capacity: {:.4} BTC", stats.latest.avg_capacity_btc());
        }
        Err(e) => println!("   ⚠ Error: {}", e),
    }
    println!();

    // 6. Mining Pool Stats
    println!("6. Getting mining pool hashrate distribution (1 week)...");
    match client.get_hashrate_distribution("1w").await {
        Ok(dist) => {
            println!("   Total blocks: {}", dist.block_count);
            println!("   Top 5 pools:");
            for pool in dist.top_pools(5) {
                println!("     - {}: {:.1}% ({} blocks)", 
                    pool.pool.name, pool.share_percent(), pool.block_count);
            }
        }
        Err(e) => println!("   ⚠ Error: {}", e),
    }
    println!();

    // 7. Difficulty Adjustment
    println!("7. Getting difficulty adjustment info...");
    match client.get_difficulty_adjustment().await {
        Ok(adj) => {
            let direction = if adj.will_increase() { "increase" } else { "decrease" };
            println!("   Expected change: {:.2}% ({})", adj.difficulty_change_percent(), direction);
            println!("   Remaining blocks: {}", adj.remaining_blocks);
            println!("   Remaining time: {:.1} days", adj.remaining_days());
            println!("   Next retarget height: {}", adj.next_retarget_height);
        }
        Err(e) => println!("   ⚠ Error: {}", e),
    }
    println!();

    // 8. WebSocket API Demo
    println!("8. WebSocket API (demo)...");
    let ws = MempoolWsClient::new();
    println!("   WebSocket URL: {}", ws.url());
    println!("   Status: {:?}", ws.status().await);
    
    // Configure subscription
    let sub = WsSubscription::new()
        .with_blocks()
        .with_fees()
        .track_address(satoshi_addr);
    
    ws.set_subscription(sub).await;
    let current_sub = ws.get_subscription().await;
    println!("   Subscriptions configured:");
    println!("     - Blocks: {}", current_sub.blocks);
    println!("     - Fees: {}", current_sub.fees);
    println!("     - Addresses tracked: {}", current_sub.addresses.len());
    println!();

    // 9. Get a specific transaction
    println!("9. Getting transaction details...");
    let txid = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";
    match client.get_tx(txid).await {
        Ok(tx) => {
            println!("   TXID: {}...", &tx.txid[..16]);
            println!("   Size: {} bytes", tx.size);
            println!("   Weight: {} WU", tx.weight);
            println!("   Fee: {} sats ({:.2} sat/vB)", tx.fee, tx.fee_rate());
            println!("   Confirmed: {}", tx.is_confirmed());
            if let Some(height) = tx.status.block_height {
                println!("   Block height: {}", height);
            }
        }
        Err(e) => println!("   ⚠ Error: {}", e),
    }
    println!();

    println!("=== Demo Complete! ===");
    println!("\nv0.2 Features demonstrated:");
    println!("  ✓ Lightning Network stats");
    println!("  ✓ Mining pool hashrate distribution");
    println!("  ✓ Difficulty adjustment info");
    println!("  ✓ WebSocket subscription API");
    
    Ok(())
}
