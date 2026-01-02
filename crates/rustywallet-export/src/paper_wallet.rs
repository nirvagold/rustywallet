//! Paper wallet export functions.

use crate::error::{ExportError, Result};
use crate::types::{AddressType, Network, PaperWallet};
use crate::export_wif;
use rustywallet_keys::prelude::PrivateKey;
use rustywallet_address::{P2PKHAddress, P2WPKHAddress, P2TRAddress, Network as AddrNetwork};

/// Generate paper wallet data from a private key.
///
/// # Example
///
/// ```rust
/// use rustywallet_export::{to_paper_wallet, Network, AddressType};
/// use rustywallet_keys::prelude::PrivateKey;
///
/// let key = PrivateKey::random();
/// let paper = to_paper_wallet(&key, Network::Mainnet, AddressType::P2PKH).unwrap();
///
/// println!("Address: {}", paper.address);
/// println!("WIF: {}", paper.wif);
/// ```
pub fn to_paper_wallet(
    key: &PrivateKey,
    network: Network,
    address_type: AddressType,
) -> Result<PaperWallet> {
    let public_key = key.public_key();
    
    let addr_network = match network {
        Network::Mainnet => AddrNetwork::BitcoinMainnet,
        Network::Testnet => AddrNetwork::BitcoinTestnet,
    };
    
    let address = match address_type {
        AddressType::P2PKH => {
            P2PKHAddress::from_public_key(&public_key, addr_network)
                .map_err(|e| ExportError::AddressError(e.to_string()))?
                .to_string()
        }
        AddressType::P2WPKH => {
            P2WPKHAddress::from_public_key(&public_key, addr_network)
                .map_err(|e| ExportError::AddressError(e.to_string()))?
                .to_string()
        }
        AddressType::P2TR => {
            P2TRAddress::from_public_key(&public_key, addr_network)
                .map_err(|e| ExportError::AddressError(e.to_string()))?
                .to_string()
        }
    };
    
    Ok(PaperWallet {
        address,
        wif: export_wif(key, network, true),
        network: network.to_string(),
        address_type: address_type.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_paper_wallet_p2pkh() {
        let key = PrivateKey::random();
        let paper = to_paper_wallet(&key, Network::Mainnet, AddressType::P2PKH).unwrap();
        
        assert!(paper.address.starts_with('1'));
        assert!(paper.wif.starts_with('K') || paper.wif.starts_with('L'));
        assert_eq!(paper.network, "mainnet");
        assert_eq!(paper.address_type, "p2pkh");
    }
    
    #[test]
    fn test_paper_wallet_p2wpkh() {
        let key = PrivateKey::random();
        let paper = to_paper_wallet(&key, Network::Mainnet, AddressType::P2WPKH).unwrap();
        
        assert!(paper.address.starts_with("bc1q"));
    }
    
    #[test]
    fn test_paper_wallet_p2tr() {
        let key = PrivateKey::random();
        let paper = to_paper_wallet(&key, Network::Mainnet, AddressType::P2TR).unwrap();
        
        assert!(paper.address.starts_with("bc1p"));
    }
    
    #[test]
    fn test_paper_wallet_testnet() {
        let key = PrivateKey::random();
        let paper = to_paper_wallet(&key, Network::Testnet, AddressType::P2PKH).unwrap();
        
        assert!(paper.address.starts_with('m') || paper.address.starts_with('n'));
        assert!(paper.wif.starts_with('c'));
    }
}
