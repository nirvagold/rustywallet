use anyhow::{anyhow, Result};
use colored::Colorize;
use rustywallet::address::{
    EthereumAddress, Network as AddressNetwork, P2PKHAddress, P2TRAddress, P2WPKHAddress,
};

use crate::utils::parse_private_key;

pub fn run(key: &str, addr_type: &str, network: &str) -> Result<()> {
    let private_key = parse_private_key(key)?;
    let public_key = private_key.public_key();

    let addr_network = match network {
        "mainnet" => AddressNetwork::BitcoinMainnet,
        "testnet" => AddressNetwork::BitcoinTestnet,
        _ => return Err(anyhow!("Invalid network: {}", network)),
    };

    println!("{}", "Address Derivation".bold());
    println!();

    let address = match addr_type {
        "legacy" => {
            let addr = P2PKHAddress::from_public_key(&public_key, addr_network)
                .map_err(|e| anyhow!("Failed to derive address: {}", e))?;
            println!("  {} Legacy (P2PKH)", "Type:".bold());
            addr.to_string()
        }
        "segwit" => {
            let addr = P2WPKHAddress::from_public_key(&public_key, addr_network)
                .map_err(|e| anyhow!("Failed to derive address: {}", e))?;
            println!("  {} SegWit (P2WPKH)", "Type:".bold());
            addr.to_string()
        }
        "taproot" => {
            let addr = P2TRAddress::from_public_key(&public_key, addr_network)
                .map_err(|e| anyhow!("Failed to derive address: {}", e))?;
            println!("  {} Taproot (P2TR)", "Type:".bold());
            addr.to_string()
        }
        "ethereum" => {
            let addr = EthereumAddress::from_public_key(&public_key)
                .map_err(|e| anyhow!("Failed to derive address: {}", e))?;
            println!("  {} Ethereum", "Type:".bold());
            addr.to_string()
        }
        _ => return Err(anyhow!("Invalid address type: {}", addr_type)),
    };

    println!("  {} {}", "Network:".bold(), network);
    println!();
    println!("  {} {}", "Address:".bold(), address.green());

    Ok(())
}
