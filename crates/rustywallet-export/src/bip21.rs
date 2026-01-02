//! BIP21 URI generation.

use crate::types::Bip21Options;

/// Generate a BIP21 URI for a Bitcoin address.
///
/// BIP21 format: `bitcoin:<address>[?amount=<amount>][&label=<label>][&message=<message>]`
///
/// # Example
///
/// ```rust
/// use rustywallet_export::{to_bip21_uri, Bip21Options};
///
/// let address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
///
/// // Simple URI
/// let uri = to_bip21_uri(address, Bip21Options::new());
/// assert_eq!(uri, "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
///
/// // With amount and label
/// let uri = to_bip21_uri(address, Bip21Options::new()
///     .with_amount(1.5)
///     .with_label("Donation"));
/// assert!(uri.contains("amount=1.5"));
/// assert!(uri.contains("label=Donation"));
/// ```
pub fn to_bip21_uri(address: &str, options: Bip21Options) -> String {
    let mut uri = format!("bitcoin:{}", address);
    let mut params = Vec::new();
    
    if let Some(amount) = options.amount {
        params.push(format!("amount={}", amount));
    }
    
    if let Some(label) = options.label {
        params.push(format!("label={}", url_encode(&label)));
    }
    
    if let Some(message) = options.message {
        params.push(format!("message={}", url_encode(&message)));
    }
    
    if !params.is_empty() {
        uri.push('?');
        uri.push_str(&params.join("&"));
    }
    
    uri
}

/// Simple URL encoding for BIP21 parameters.
fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
            ' ' => result.push_str("%20"),
            _ => {
                for byte in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_simple_uri() {
        let uri = to_bip21_uri("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Bip21Options::new());
        assert_eq!(uri, "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }
    
    #[test]
    fn test_uri_with_amount() {
        let uri = to_bip21_uri(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            Bip21Options::new().with_amount(1.5),
        );
        assert_eq!(uri, "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=1.5");
    }
    
    #[test]
    fn test_uri_with_label() {
        let uri = to_bip21_uri(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            Bip21Options::new().with_label("Donation"),
        );
        assert_eq!(uri, "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=Donation");
    }
    
    #[test]
    fn test_uri_with_all_options() {
        let uri = to_bip21_uri(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            Bip21Options::new()
                .with_amount(0.001)
                .with_label("Coffee")
                .with_message("Thanks!"),
        );
        assert!(uri.contains("amount=0.001"));
        assert!(uri.contains("label=Coffee"));
        assert!(uri.contains("message=Thanks"));
    }
    
    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("test"), "test");
    }
}
