use anyhow::{anyhow, Result};
use colored::Colorize;
use rustywallet::address::{
    EthereumAddress, Network as AddressNetwork, P2PKHAddress, P2TRAddress, P2WPKHAddress,
};
use rustywallet::hd::{
    extended_key::ExtendedPrivateKey, network::Network as HdNetwork, path::DerivationPath,
};
use rustywallet::mnemonic::Mnemonic;

pub fn run(
    mnemonic_phrase: &str,
    passphrase: Option<&str>,
    path: &str,
    address_type: &str,
    network: &str,
) -> Result<()> {
    // Parse mnemonic
    let mnemonic =
        Mnemonic::from_phrase(mnemonic_phrase).map_err(|e| anyhow!("Invalid mnemonic: {}", e))?;

    // Derive seed
    let pass = passphrase.unwrap_or("");
    let seed = mnemonic.to_seed(pass);

    // Parse network
    let hd_network = match network {
        "mainnet" => HdNetwork::Mainnet,
        "testnet" => HdNetwork::Testnet,
        _ => return Err(anyhow!("Invalid network: {}", network)),
    };

    let addr_network = match network {
        "mainnet" => AddressNetwork::BitcoinMainnet,
        "testnet" => AddressNetwork::BitcoinTestnet,
        _ => unreachable!(),
    };

    // Parse derivation path
    let derivation_path: DerivationPath =
        path.parse().map_err(|e| anyhow!("Invalid path: {}", e))?;

    // Derive master key
    let master = ExtendedPrivateKey::from_seed(seed.as_bytes(), hd_network)
        .map_err(|e| anyhow!("Failed to derive master key: {}", e))?;

    // Derive child key
    let derived = master
        .derive_path(&derivation_path)
        .map_err(|e| anyhow!("Failed to derive path: {}", e))?;

    let private_key = derived
        .private_key()
        .map_err(|e| anyhow!("Failed to get private key: {}", e))?;
    let public_key = private_key.public_key();

    println!("{}", "HD Wallet Derivation".bold());
    println!();
    println!("  {} {}", "Path:".bold(), path);
    println!("  {} {}", "Network:".bold(), network);
    println!();

    // Private key
    println!(
        "  {} {}",
        "Private Key:".bold(),
        private_key.to_hex().yellow()
    );

    // Public key
    println!(
        "  {} {}",
        "Public Key:".bold(),
        hex::encode(public_key.to_compressed())
    );

    // Address
    let address = match address_type {
        "legacy" => {
            let addr = P2PKHAddress::from_public_key(&public_key, addr_network)
                .map_err(|e| anyhow!("Failed to derive address: {}", e))?;
            println!("  {} Legacy (P2PKH)", "Address Type:".bold());
            addr.to_string()
        }
        "segwit" => {
            let addr = P2WPKHAddress::from_public_key(&public_key, addr_network)
                .map_err(|e| anyhow!("Failed to derive address: {}", e))?;
            println!("  {} SegWit (P2WPKH)", "Address Type:".bold());
            addr.to_string()
        }
        "taproot" => {
            let addr = P2TRAddress::from_public_key(&public_key, addr_network)
                .map_err(|e| anyhow!("Failed to derive address: {}", e))?;
            println!("  {} Taproot (P2TR)", "Address Type:".bold());
            addr.to_string()
        }
        "ethereum" => {
            let addr = EthereumAddress::from_public_key(&public_key)
                .map_err(|e| anyhow!("Failed to derive address: {}", e))?;
            println!("  {} Ethereum", "Address Type:".bold());
            addr.to_string()
        }
        _ => return Err(anyhow!("Invalid address type: {}", address_type)),
    };

    println!();
    println!("  {} {}", "Address:".bold(), address.green());

    println!();
    println!(
        "{}",
        "⚠️  Keep your private key and mnemonic safe!".yellow()
    );

    Ok(())
}
