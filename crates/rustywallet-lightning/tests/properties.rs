//! Property-based tests for rustywallet-lightning.

use proptest::prelude::*;
use rustywallet_lightning::bolt12::{Bolt12Offer, OfferBuilder, OfferAmount};

/// Generate a random description
fn arb_description() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 ]{1,100}".prop_map(|s| s.trim().to_string())
        .prop_filter("non-empty", |s| !s.is_empty())
}

/// Generate a random amount in millisatoshis
fn arb_amount_msats() -> impl Strategy<Value = u64> {
    1u64..1_000_000_000_000u64 // 1 msat to 10 BTC
}

/// Generate a random expiry offset in seconds
fn arb_expiry_offset() -> impl Strategy<Value = u64> {
    60u64..86400 * 365 // 1 minute to 1 year
}

/// Generate a random issuer name
fn arb_issuer() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 ]{1,50}".prop_map(|s| s.trim().to_string())
        .prop_filter("non-empty", |s| !s.is_empty())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // **Feature: ecosystem-upgrade-v2, Property 20: BOLT12 Offer Round-Trip**
    // **Validates: Requirements 18.1, 18.2, 18.5**
    //
    // For any valid BOLT12 offer, parsing then encoding SHALL produce
    // an equivalent offer string.
    #[test]
    fn prop_bolt12_offer_roundtrip(
        description in arb_description(),
        amount in arb_amount_msats(),
    ) {
        // Build an offer
        let offer = OfferBuilder::new()
            .description(&description)
            .amount_msats(amount)
            .build()
            .unwrap();

        // Encode to string
        let encoded = offer.encode();
        prop_assert!(encoded.starts_with("lno1"), "Encoded offer should start with 'lno1'");

        // Parse back
        let parsed = Bolt12Offer::parse(&encoded);
        prop_assert!(parsed.is_ok(), "Should be able to parse encoded offer");

        let parsed = parsed.unwrap();

        // Verify fields match
        prop_assert_eq!(
            parsed.description(),
            description,
            "Description should match after roundtrip"
        );

        prop_assert_eq!(
            parsed.amount().and_then(|a| a.as_msats()),
            Some(amount),
            "Amount should match after roundtrip"
        );
    }

    // Test roundtrip with expiry
    #[test]
    fn prop_bolt12_offer_roundtrip_with_expiry(
        description in arb_description(),
        expiry_offset in arb_expiry_offset(),
    ) {
        let offer = OfferBuilder::new()
            .description(&description)
            .expires_in(expiry_offset)
            .build()
            .unwrap();

        let encoded = offer.encode();
        let parsed = Bolt12Offer::parse(&encoded).unwrap();

        prop_assert_eq!(
            parsed.description(),
            description,
            "Description should match"
        );

        prop_assert!(
            parsed.expiry().is_some(),
            "Expiry should be present"
        );
    }

    // Test roundtrip with issuer
    #[test]
    fn prop_bolt12_offer_roundtrip_with_issuer(
        description in arb_description(),
        issuer in arb_issuer(),
    ) {
        let offer = OfferBuilder::new()
            .description(&description)
            .issuer(&issuer)
            .build()
            .unwrap();

        let encoded = offer.encode();
        let parsed = Bolt12Offer::parse(&encoded).unwrap();

        prop_assert_eq!(
            parsed.description(),
            description,
            "Description should match"
        );

        prop_assert_eq!(
            parsed.issuer(),
            Some(issuer.as_str()),
            "Issuer should match"
        );
    }

    // Test that different offers have different IDs
    #[test]
    fn prop_bolt12_offer_unique_ids(
        desc1 in arb_description(),
        desc2 in arb_description(),
    ) {
        prop_assume!(desc1 != desc2);

        let offer1 = OfferBuilder::new()
            .description(&desc1)
            .build()
            .unwrap();

        let offer2 = OfferBuilder::new()
            .description(&desc2)
            .build()
            .unwrap();

        prop_assert_ne!(
            offer1.offer_id(),
            offer2.offer_id(),
            "Different offers should have different IDs"
        );
    }

    // Test amount types
    #[test]
    fn prop_bolt12_amount_fixed(amount in arb_amount_msats()) {
        let offer_amount = OfferAmount::msats(amount);
        
        prop_assert!(offer_amount.is_fixed(), "Should be fixed amount");
        prop_assert_eq!(offer_amount.as_msats(), Some(amount), "Amount should match");
    }

    // Test variable amount
    #[test]
    fn prop_bolt12_amount_variable(_dummy in 0u8..1) {
        let offer_amount = OfferAmount::variable();
        
        prop_assert!(!offer_amount.is_fixed(), "Should not be fixed amount");
        prop_assert_eq!(offer_amount.as_msats(), None, "Variable amount has no msats");
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_basic_offer_roundtrip() {
        let offer = OfferBuilder::new()
            .description("Test offer")
            .amount_msats(10_000)
            .build()
            .unwrap();

        let encoded = offer.encode();
        assert!(encoded.starts_with("lno1"));

        let parsed = Bolt12Offer::parse(&encoded).unwrap();
        assert_eq!(parsed.description(), "Test offer");
        assert_eq!(parsed.amount().unwrap().as_msats(), Some(10_000));
    }

    #[test]
    fn test_offer_with_all_fields() {
        let offer = OfferBuilder::new()
            .description("Complete offer")
            .amount_msats(50_000)
            .issuer("Test Issuer")
            .expires_in(3600)
            .quantity_max(10)
            .build()
            .unwrap();

        let encoded = offer.encode();
        let parsed = Bolt12Offer::parse(&encoded).unwrap();

        assert_eq!(parsed.description(), "Complete offer");
        assert_eq!(parsed.amount().unwrap().as_msats(), Some(50_000));
        assert_eq!(parsed.issuer(), Some("Test Issuer"));
        assert!(parsed.expiry().is_some());
        assert_eq!(parsed.quantity_max(), Some(10));
    }

    #[test]
    fn test_offer_id_deterministic() {
        let offer1 = OfferBuilder::new()
            .description("Same offer")
            .amount_msats(1000)
            .build()
            .unwrap();

        let offer2 = OfferBuilder::new()
            .description("Same offer")
            .amount_msats(1000)
            .build()
            .unwrap();

        // Same parameters should produce same offer ID
        assert_eq!(offer1.offer_id(), offer2.offer_id());
    }

    #[test]
    fn test_bitcoin_mainnet_support() {
        let offer = OfferBuilder::new()
            .description("Bitcoin offer")
            .build()
            .unwrap();

        // Empty chains means Bitcoin mainnet only
        assert!(offer.supports_bitcoin_mainnet());
    }

    #[test]
    fn test_offer_not_expired() {
        let offer = OfferBuilder::new()
            .description("Future offer")
            .expires_in(3600) // 1 hour from now
            .build()
            .unwrap();

        assert!(!offer.is_expired());
    }

    #[test]
    fn test_empty_description_fails() {
        let result = OfferBuilder::new().build();
        assert!(result.is_err());
    }
}
