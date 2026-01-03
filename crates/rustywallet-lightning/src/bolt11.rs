//! BOLT11 invoice parsing and creation.
//!
//! This module provides types for working with Lightning Network invoices
//! as specified in BOLT11.

use crate::error::LightningError;
use crate::payment::PaymentHash;
use crate::route::RouteHint;
use std::time::{SystemTime, UNIX_EPOCH};

/// A parsed BOLT11 invoice.
#[derive(Debug, Clone)]
pub struct Bolt11Invoice {
    /// Human-readable part (network prefix)
    #[allow(dead_code)]
    hrp: String,
    /// Invoice data
    data: InvoiceData,
    /// Raw invoice string
    raw: String,
}

impl Bolt11Invoice {
    /// Parse a BOLT11 invoice string.
    ///
    /// Note: This is a simplified parser that extracts basic information.
    /// For full BOLT11 compliance, consider using a dedicated library.
    pub fn parse(invoice: &str) -> Result<Self, LightningError> {
        let invoice = invoice.to_lowercase();
        
        // Check prefix
        if !invoice.starts_with("ln") {
            return Err(LightningError::InvalidInvoice(
                "Invoice must start with 'ln'".into(),
            ));
        }

        // Extract HRP (everything before '1')
        let separator_pos = invoice.rfind('1').ok_or_else(|| {
            LightningError::InvalidInvoice("Missing separator '1'".into())
        })?;

        let hrp = invoice[..separator_pos].to_string();
        
        // Determine network from HRP
        let network = if hrp.starts_with("lnbc") {
            Network::Mainnet
        } else if hrp.starts_with("lntb") {
            Network::Testnet
        } else if hrp.starts_with("lnbcrt") {
            Network::Regtest
        } else {
            return Err(LightningError::InvalidInvoice(format!(
                "Unknown network prefix: {}",
                hrp
            )));
        };

        // Extract amount from HRP if present
        let amount_msat = Self::parse_amount(&hrp)?;

        // For now, create a basic invoice data structure
        // Full parsing would require bech32 decoding of the data part
        let data = InvoiceData {
            network,
            amount_msat,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            expiry: 3600, // Default 1 hour
            payment_hash: None,
            description: None,
            description_hash: None,
            payee_pubkey: None,
            route_hints: Vec::new(),
            min_final_cltv_expiry: 18,
        };

        Ok(Self {
            hrp,
            data,
            raw: invoice,
        })
    }

    /// Parse amount from HRP.
    fn parse_amount(hrp: &str) -> Result<Option<u64>, LightningError> {
        // Remove network prefix using strip_prefix
        let amount_str = if let Some(stripped) = hrp.strip_prefix("lnbcrt") {
            stripped
        } else if let Some(stripped) = hrp.strip_prefix("lnbc") {
            stripped
        } else if let Some(stripped) = hrp.strip_prefix("lntb") {
            stripped
        } else {
            return Ok(None);
        };

        if amount_str.is_empty() {
            return Ok(None);
        }

        // Parse amount with multiplier
        let (num_str, multiplier) = if let Some(last) = amount_str.chars().last() {
            match last {
                'm' => (&amount_str[..amount_str.len()-1], 100_000_000u64), // milli-BTC
                'u' => (&amount_str[..amount_str.len()-1], 100_000u64),     // micro-BTC
                'n' => (&amount_str[..amount_str.len()-1], 100u64),         // nano-BTC
                'p' => (&amount_str[..amount_str.len()-1], 1u64),           // pico-BTC (0.1 msat)
                _ => (amount_str, 100_000_000_000u64),                       // BTC
            }
        } else {
            return Ok(None);
        };

        let amount: u64 = num_str.parse().map_err(|_| {
            LightningError::InvalidInvoice(format!("Invalid amount: {}", amount_str))
        })?;

        Ok(Some(amount * multiplier))
    }

    /// Get the network.
    pub fn network(&self) -> Network {
        self.data.network
    }

    /// Get the amount in millisatoshis.
    pub fn amount_msat(&self) -> Option<u64> {
        self.data.amount_msat
    }

    /// Get the payment hash.
    pub fn payment_hash(&self) -> Option<&PaymentHash> {
        self.data.payment_hash.as_ref()
    }

    /// Get the description.
    pub fn description(&self) -> Option<&str> {
        self.data.description.as_deref()
    }

    /// Get the expiry time in seconds.
    pub fn expiry(&self) -> u64 {
        self.data.expiry
    }

    /// Get the timestamp.
    pub fn timestamp(&self) -> u64 {
        self.data.timestamp
    }

    /// Check if the invoice has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        now > self.data.timestamp + self.data.expiry
    }

    /// Get the raw invoice string.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Get the invoice data.
    pub fn data(&self) -> &InvoiceData {
        &self.data
    }
}

/// Invoice data extracted from a BOLT11 invoice.
#[derive(Debug, Clone)]
pub struct InvoiceData {
    /// Network (mainnet, testnet, regtest)
    pub network: Network,
    /// Amount in millisatoshis
    pub amount_msat: Option<u64>,
    /// Creation timestamp (Unix seconds)
    pub timestamp: u64,
    /// Expiry time in seconds
    pub expiry: u64,
    /// Payment hash
    pub payment_hash: Option<PaymentHash>,
    /// Description string
    pub description: Option<String>,
    /// Description hash (for long descriptions)
    pub description_hash: Option<[u8; 32]>,
    /// Payee public key
    pub payee_pubkey: Option<[u8; 33]>,
    /// Route hints
    pub route_hints: Vec<RouteHint>,
    /// Minimum final CLTV expiry
    pub min_final_cltv_expiry: u32,
}

/// Lightning Network type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Bitcoin mainnet
    Mainnet,
    /// Bitcoin testnet
    Testnet,
    /// Bitcoin regtest
    Regtest,
}

impl Network {
    /// Get the HRP prefix for this network.
    pub fn hrp_prefix(&self) -> &'static str {
        match self {
            Network::Mainnet => "lnbc",
            Network::Testnet => "lntb",
            Network::Regtest => "lnbcrt",
        }
    }
}

/// Builder for creating BOLT11 invoices.
pub struct InvoiceBuilder {
    network: Network,
    amount_msat: Option<u64>,
    description: Option<String>,
    payment_hash: Option<PaymentHash>,
    expiry: u64,
    route_hints: Vec<RouteHint>,
    min_final_cltv_expiry: u32,
}

impl InvoiceBuilder {
    /// Create a new invoice builder.
    pub fn new(network: Network) -> Self {
        Self {
            network,
            amount_msat: None,
            description: None,
            payment_hash: None,
            expiry: 3600, // 1 hour default
            route_hints: Vec::new(),
            min_final_cltv_expiry: 18,
        }
    }

    /// Set the amount in millisatoshis.
    pub fn amount_msat(mut self, amount: u64) -> Self {
        self.amount_msat = Some(amount);
        self
    }

    /// Set the amount in satoshis.
    pub fn amount_sats(mut self, sats: u64) -> Self {
        self.amount_msat = Some(sats * 1000);
        self
    }

    /// Set the description.
    pub fn description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }

    /// Set the payment hash.
    pub fn payment_hash(mut self, hash: PaymentHash) -> Self {
        self.payment_hash = Some(hash);
        self
    }

    /// Set the expiry time in seconds.
    pub fn expiry(mut self, seconds: u64) -> Self {
        self.expiry = seconds;
        self
    }

    /// Add a route hint.
    pub fn route_hint(mut self, hint: RouteHint) -> Self {
        self.route_hints.push(hint);
        self
    }

    /// Set the minimum final CLTV expiry.
    pub fn min_final_cltv_expiry(mut self, blocks: u32) -> Self {
        self.min_final_cltv_expiry = blocks;
        self
    }

    /// Build the invoice data.
    ///
    /// Note: This creates the invoice data structure but does not
    /// encode it to a full BOLT11 string (which requires signing).
    pub fn build(self) -> Result<InvoiceData, LightningError> {
        let payment_hash = self.payment_hash.ok_or_else(|| {
            LightningError::InvalidInvoice("Payment hash is required".into())
        })?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(InvoiceData {
            network: self.network,
            amount_msat: self.amount_msat,
            timestamp,
            expiry: self.expiry,
            payment_hash: Some(payment_hash),
            description: self.description,
            description_hash: None,
            payee_pubkey: None,
            route_hints: self.route_hints,
            min_final_cltv_expiry: self.min_final_cltv_expiry,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payment::PaymentPreimage;

    #[test]
    fn test_parse_mainnet_invoice() {
        // Simple mainnet invoice prefix
        let invoice = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";
        
        let parsed = Bolt11Invoice::parse(invoice).unwrap();
        assert_eq!(parsed.network(), Network::Mainnet);
    }

    #[test]
    fn test_parse_testnet_invoice() {
        let invoice = "lntb1u1p0xxxx";
        let parsed = Bolt11Invoice::parse(invoice).unwrap();
        assert_eq!(parsed.network(), Network::Testnet);
    }

    #[test]
    fn test_parse_amount() {
        // 1 mBTC = 100,000,000 msat
        assert_eq!(Bolt11Invoice::parse_amount("lnbc1m").unwrap(), Some(100_000_000));
        
        // 1 uBTC = 100,000 msat
        assert_eq!(Bolt11Invoice::parse_amount("lnbc1u").unwrap(), Some(100_000));
        
        // 1 nBTC = 100 msat
        assert_eq!(Bolt11Invoice::parse_amount("lnbc1n").unwrap(), Some(100));
    }

    #[test]
    fn test_invoice_builder() {
        let preimage = PaymentPreimage::random();
        let payment_hash = preimage.payment_hash();

        let data = InvoiceBuilder::new(Network::Mainnet)
            .amount_sats(10000)
            .description("Test payment")
            .payment_hash(payment_hash)
            .expiry(3600)
            .build()
            .unwrap();

        assert_eq!(data.network, Network::Mainnet);
        assert_eq!(data.amount_msat, Some(10_000_000));
        assert_eq!(data.description, Some("Test payment".to_string()));
    }

    #[test]
    fn test_network_hrp() {
        assert_eq!(Network::Mainnet.hrp_prefix(), "lnbc");
        assert_eq!(Network::Testnet.hrp_prefix(), "lntb");
        assert_eq!(Network::Regtest.hrp_prefix(), "lnbcrt");
    }
}
