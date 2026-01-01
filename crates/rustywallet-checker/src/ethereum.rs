//! Ethereum balance checker using public RPC endpoints

use crate::error::CheckerError;
use serde::{Deserialize, Serialize};

/// Ethereum balance result
#[derive(Debug, Clone)]
pub struct EthereumBalance {
    /// The address checked
    pub address: String,
    /// Balance in wei (as string due to large numbers)
    pub balance_wei: String,
    /// Balance in ETH (floating point approximation)
    pub balance_eth: f64,
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    method: &'static str,
    params: Vec<serde_json::Value>,
    id: u32,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    result: Option<String>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    message: String,
}

/// Public Ethereum RPC endpoints
const ETH_RPC_ENDPOINTS: &[&str] = &[
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
    "https://ethereum.publicnode.com",
    "https://1rpc.io/eth",
];

/// Check Ethereum address balance using public RPC
///
/// # Arguments
/// * `address` - Ethereum address (0x prefixed)
///
/// # Returns
/// Balance information in wei and ETH
///
/// # Example
/// ```no_run
/// use rustywallet_checker::ethereum::check_eth_balance;
///
/// #[tokio::main]
/// async fn main() {
///     let balance = check_eth_balance("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").await.unwrap();
///     println!("Balance: {} ETH", balance.balance_eth);
/// }
/// ```
pub async fn check_eth_balance(address: &str) -> Result<EthereumBalance, CheckerError> {
    // Validate address format
    if !is_valid_eth_address(address) {
        return Err(CheckerError::InvalidAddress(address.to_string()));
    }

    // Normalize address (ensure 0x prefix)
    let address = if address.starts_with("0x") {
        address.to_string()
    } else {
        format!("0x{}", address)
    };

    // Try each RPC endpoint until one works
    let mut last_error = None;
    for endpoint in ETH_RPC_ENDPOINTS {
        match fetch_balance(endpoint, &address).await {
            Ok(balance) => return Ok(balance),
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        CheckerError::ApiError("All RPC endpoints failed".to_string())
    }))
}

async fn fetch_balance(endpoint: &str, address: &str) -> Result<EthereumBalance, CheckerError> {
    let client = reqwest::Client::new();

    let request = JsonRpcRequest {
        jsonrpc: "2.0",
        method: "eth_getBalance",
        params: vec![
            serde_json::Value::String(address.to_string()),
            serde_json::Value::String("latest".to_string()),
        ],
        id: 1,
    };

    let response = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .header("User-Agent", "rustywallet-checker/0.1")
        .json(&request)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?;

    if response.status() == 429 {
        return Err(CheckerError::RateLimited);
    }

    if !response.status().is_success() {
        return Err(CheckerError::ApiError(format!(
            "RPC returned status {}",
            response.status()
        )));
    }

    let data: JsonRpcResponse = response
        .json()
        .await
        .map_err(|e| CheckerError::ParseError(e.to_string()))?;

    if let Some(error) = data.error {
        return Err(CheckerError::ApiError(error.message));
    }

    let balance_hex = data
        .result
        .ok_or_else(|| CheckerError::ParseError("No result in response".to_string()))?;

    // Parse hex balance (remove 0x prefix)
    let balance_wei = parse_hex_balance(&balance_hex)?;
    let balance_eth = wei_to_eth(&balance_wei);

    Ok(EthereumBalance {
        address: address.to_string(),
        balance_wei,
        balance_eth,
    })
}

/// Parse hex balance string to decimal string
fn parse_hex_balance(hex: &str) -> Result<String, CheckerError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);

    if hex == "0" || hex.is_empty() {
        return Ok("0".to_string());
    }

    // Parse hex to u128 (sufficient for most balances)
    // For very large balances, we'd need a big integer library
    let value = u128::from_str_radix(hex, 16)
        .map_err(|e| CheckerError::ParseError(format!("Invalid hex balance: {}", e)))?;

    Ok(value.to_string())
}

/// Convert wei string to ETH (approximate)
fn wei_to_eth(wei: &str) -> f64 {
    let wei_value: f64 = wei.parse().unwrap_or(0.0);
    wei_value / 1_000_000_000_000_000_000.0
}

/// Basic Ethereum address validation
fn is_valid_eth_address(address: &str) -> bool {
    let addr = address.strip_prefix("0x").unwrap_or(address);

    // Must be 40 hex characters
    if addr.len() != 40 {
        return false;
    }

    // Must be valid hex
    addr.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_eth_addresses() {
        assert!(is_valid_eth_address(
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        ));
        assert!(is_valid_eth_address(
            "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        ));
        assert!(is_valid_eth_address(
            "0x0000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_invalid_eth_addresses() {
        assert!(!is_valid_eth_address("invalid"));
        assert!(!is_valid_eth_address("0x123")); // too short
        assert!(!is_valid_eth_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")); // bitcoin
    }

    #[test]
    fn test_parse_hex_balance() {
        assert_eq!(parse_hex_balance("0x0").unwrap(), "0");
        assert_eq!(parse_hex_balance("0x1").unwrap(), "1");
        assert_eq!(parse_hex_balance("0xa").unwrap(), "10");
        assert_eq!(parse_hex_balance("0x64").unwrap(), "100");
    }

    #[test]
    fn test_wei_to_eth() {
        assert_eq!(wei_to_eth("1000000000000000000"), 1.0);
        assert_eq!(wei_to_eth("500000000000000000"), 0.5);
        assert_eq!(wei_to_eth("0"), 0.0);
    }
}
