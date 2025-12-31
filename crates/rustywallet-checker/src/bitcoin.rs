//! Bitcoin balance checker using blockchain.info API

use crate::error::CheckerError;
use serde::Deserialize;

/// Bitcoin balance result
#[derive(Debug, Clone)]
pub struct BitcoinBalance {
    /// The address checked
    pub address: String,
    /// Confirmed balance in satoshis
    pub balance: u64,
    /// Unconfirmed balance in satoshis
    pub unconfirmed: i64,
    /// Total received in satoshis
    pub total_received: u64,
    /// Total sent in satoshis
    pub total_sent: u64,
    /// Number of transactions
    pub tx_count: u64,
}

#[derive(Debug, Deserialize)]
struct BlockchainInfoResponse {
    #[serde(rename = "final_balance")]
    final_balance: u64,
    #[serde(rename = "total_received")]
    total_received: u64,
    #[serde(rename = "total_sent")]
    total_sent: u64,
    #[serde(rename = "n_tx")]
    n_tx: u64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct BlockstreamResponse {
    address: String,
    chain_stats: ChainStats,
    mempool_stats: MempoolStats,
}

#[derive(Debug, Deserialize)]
struct ChainStats {
    funded_txo_sum: u64,
    spent_txo_sum: u64,
    tx_count: u64,
}

#[derive(Debug, Deserialize)]
struct MempoolStats {
    funded_txo_sum: u64,
    spent_txo_sum: u64,
}

/// Check Bitcoin address balance using blockchain.info API
///
/// # Arguments
/// * `address` - Bitcoin address (any format: legacy, segwit, taproot)
///
/// # Returns
/// Balance information including confirmed and unconfirmed amounts
///
/// # Example
/// ```no_run
/// use rustywallet_checker::bitcoin::check_btc_balance;
///
/// #[tokio::main]
/// async fn main() {
///     let balance = check_btc_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await.unwrap();
///     println!("Balance: {} satoshis", balance.balance);
/// }
/// ```
pub async fn check_btc_balance(address: &str) -> Result<BitcoinBalance, CheckerError> {
    // Validate address format (basic check)
    if !is_valid_btc_address(address) {
        return Err(CheckerError::InvalidAddress(address.to_string()));
    }

    // Try blockstream.info first (supports all address types)
    match check_via_blockstream(address).await {
        Ok(balance) => return Ok(balance),
        Err(_) => {
            // Fallback to blockchain.info for legacy addresses
            if address.starts_with('1') || address.starts_with('3') {
                return check_via_blockchain_info(address).await;
            }
        }
    }

    // If blockstream failed and it's not a legacy address, return error
    Err(CheckerError::ApiError(
        "Failed to fetch balance from all providers".to_string(),
    ))
}

async fn check_via_blockstream(address: &str) -> Result<BitcoinBalance, CheckerError> {
    let url = format!("https://blockstream.info/api/address/{}", address);
    let client = reqwest::Client::new();

    let response = client
        .get(&url)
        .header("User-Agent", "rustywallet-checker/0.1")
        .send()
        .await?;

    if response.status() == 429 {
        return Err(CheckerError::RateLimited);
    }

    if !response.status().is_success() {
        return Err(CheckerError::ApiError(format!(
            "API returned status {}",
            response.status()
        )));
    }

    let data: BlockstreamResponse = response
        .json()
        .await
        .map_err(|e| CheckerError::ParseError(e.to_string()))?;

    let confirmed_balance = data.chain_stats.funded_txo_sum - data.chain_stats.spent_txo_sum;
    let unconfirmed =
        data.mempool_stats.funded_txo_sum as i64 - data.mempool_stats.spent_txo_sum as i64;

    Ok(BitcoinBalance {
        address: address.to_string(),
        balance: confirmed_balance,
        unconfirmed,
        total_received: data.chain_stats.funded_txo_sum,
        total_sent: data.chain_stats.spent_txo_sum,
        tx_count: data.chain_stats.tx_count,
    })
}

async fn check_via_blockchain_info(address: &str) -> Result<BitcoinBalance, CheckerError> {
    let url = format!(
        "https://blockchain.info/rawaddr/{}?limit=0",
        address
    );
    let client = reqwest::Client::new();

    let response = client
        .get(&url)
        .header("User-Agent", "rustywallet-checker/0.1")
        .send()
        .await?;

    if response.status() == 429 {
        return Err(CheckerError::RateLimited);
    }

    if !response.status().is_success() {
        return Err(CheckerError::ApiError(format!(
            "API returned status {}",
            response.status()
        )));
    }

    let data: BlockchainInfoResponse = response
        .json()
        .await
        .map_err(|e| CheckerError::ParseError(e.to_string()))?;

    Ok(BitcoinBalance {
        address: address.to_string(),
        balance: data.final_balance,
        unconfirmed: 0, // blockchain.info doesn't separate unconfirmed in this endpoint
        total_received: data.total_received,
        total_sent: data.total_sent,
        tx_count: data.n_tx,
    })
}

/// Basic Bitcoin address validation
fn is_valid_btc_address(address: &str) -> bool {
    let len = address.len();

    // Legacy P2PKH (starts with 1)
    if address.starts_with('1') && (25..=34).contains(&len) {
        return true;
    }

    // Legacy P2SH (starts with 3)
    if address.starts_with('3') && (25..=34).contains(&len) {
        return true;
    }

    // SegWit (starts with bc1q)
    if address.starts_with("bc1q") && (42..=62).contains(&len) {
        return true;
    }

    // Taproot (starts with bc1p)
    if address.starts_with("bc1p") && len == 62 {
        return true;
    }

    // Testnet addresses
    if (address.starts_with('m') || address.starts_with('n') || address.starts_with('2'))
        && (25..=34).contains(&len)
    {
        return true;
    }

    if address.starts_with("tb1") && len >= 42 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_btc_addresses() {
        // Legacy
        assert!(is_valid_btc_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        // SegWit
        assert!(is_valid_btc_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        ));
        // Taproot
        assert!(is_valid_btc_address(
            "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"
        ));
    }

    #[test]
    fn test_invalid_btc_addresses() {
        assert!(!is_valid_btc_address("invalid"));
        assert!(!is_valid_btc_address("0x1234"));
        assert!(!is_valid_btc_address(""));
    }
}
