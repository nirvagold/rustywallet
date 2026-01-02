//! CSV export functions.

use crate::error::{ExportError, Result};
use crate::types::{CsvColumn, CsvOptions, Network};
use crate::{export_wif, export_hex, HexOptions};
use rustywallet_keys::prelude::PrivateKey;
use rustywallet_keys::public_key::PublicKeyFormat;
use rustywallet_address::{P2PKHAddress, Network as AddrNetwork};

/// Export multiple private keys to CSV format.
///
/// # Example
///
/// ```rust
/// use rustywallet_export::{export_csv, CsvOptions, CsvColumn, Network};
/// use rustywallet_keys::prelude::PrivateKey;
///
/// let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::random()).collect();
/// let csv = export_csv(&keys, CsvOptions::new()).unwrap();
/// println!("{}", csv);
/// ```
pub fn export_csv(keys: &[PrivateKey], options: CsvOptions) -> Result<String> {
    let mut lines = Vec::new();
    
    // Header row
    if options.header {
        let headers: Vec<&str> = options.columns.iter().map(|c| c.header()).collect();
        lines.push(headers.join(","));
    }
    
    // Data rows
    for key in keys {
        let row = build_csv_row(key, &options)?;
        lines.push(row);
    }
    
    Ok(lines.join("\n"))
}

/// Build a single CSV row for a key.
fn build_csv_row(key: &PrivateKey, options: &CsvOptions) -> Result<String> {
    let public_key = key.public_key();
    
    let addr_network = match options.network {
        Network::Mainnet => AddrNetwork::BitcoinMainnet,
        Network::Testnet => AddrNetwork::BitcoinTestnet,
    };
    
    let mut values = Vec::new();
    
    for col in &options.columns {
        let value = match col {
            CsvColumn::Address => {
                P2PKHAddress::from_public_key(&public_key, addr_network)
                    .map_err(|e| ExportError::AddressError(e.to_string()))?
                    .to_string()
            }
            CsvColumn::Wif => export_wif(key, options.network, true),
            CsvColumn::Hex => export_hex(key, HexOptions::new()),
            CsvColumn::PublicKey => public_key.to_hex(PublicKeyFormat::Compressed),
            CsvColumn::Network => options.network.to_string(),
        };
        
        // Escape value if it contains comma or quote
        let escaped = escape_csv_value(&value);
        values.push(escaped);
    }
    
    Ok(values.join(","))
}

/// Escape a CSV value if needed.
fn escape_csv_value(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_export_csv_default() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::random()).collect();
        let csv = export_csv(&keys, CsvOptions::new()).unwrap();
        
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 4); // 1 header + 3 data rows
        assert_eq!(lines[0], "address,wif,hex");
    }
    
    #[test]
    fn test_export_csv_no_header() {
        let keys: Vec<PrivateKey> = (0..2).map(|_| PrivateKey::random()).collect();
        let csv = export_csv(&keys, CsvOptions::new().with_header(false)).unwrap();
        
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2); // No header, just 2 data rows
    }
    
    #[test]
    fn test_export_csv_custom_columns() {
        let keys: Vec<PrivateKey> = (0..1).map(|_| PrivateKey::random()).collect();
        let options = CsvOptions::new()
            .with_columns(vec![CsvColumn::Wif, CsvColumn::Address]);
        let csv = export_csv(&keys, options).unwrap();
        
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "wif,address");
    }
    
    #[test]
    fn test_escape_csv_value() {
        assert_eq!(escape_csv_value("simple"), "simple");
        assert_eq!(escape_csv_value("with,comma"), "\"with,comma\"");
        assert_eq!(escape_csv_value("with\"quote"), "\"with\"\"quote\"");
    }
}
