use anyhow::{anyhow, Result};
use rustywallet::keys::{network::Network as KeyNetwork, private_key::PrivateKey};

/// Parse a private key from hex or WIF format
pub fn parse_private_key(input: &str) -> Result<PrivateKey> {
    let input = input.trim();

    // Try WIF first (starts with 5, K, L, c, 9)
    if input.starts_with('5')
        || input.starts_with('K')
        || input.starts_with('L')
        || input.starts_with('c')
        || input.starts_with('9')
    {
        return PrivateKey::from_wif(input).map_err(|e| anyhow!("Invalid WIF: {}", e));
    }

    // Try hex
    let hex_input = input.strip_prefix("0x").unwrap_or(input);
    PrivateKey::from_hex(hex_input).map_err(|e| anyhow!("Invalid hex key: {}", e))
}

/// Parse network string to KeyNetwork
pub fn parse_key_network(network: &str) -> Result<KeyNetwork> {
    match network {
        "mainnet" => Ok(KeyNetwork::Mainnet),
        "testnet" => Ok(KeyNetwork::Testnet),
        _ => Err(anyhow!("Invalid network: {}", network)),
    }
}
