//! Integration tests for rustywallet-lightning.

use crate::prelude::*;

/// Generate a random 64-byte seed for testing.
fn random_seed() -> [u8; 64] {
    use rand::RngCore;
    let mut seed = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

#[test]
fn test_full_payment_flow() {
    // 1. Generate payment preimage and hash
    let preimage = PaymentPreimage::random();
    let payment_hash = preimage.payment_hash();

    // 2. Verify the hash matches
    assert!(payment_hash.verify(&preimage));

    // 3. Hex roundtrip
    let hash_hex = payment_hash.to_hex();
    let recovered_hash = PaymentHash::from_hex(&hash_hex).unwrap();
    assert_eq!(payment_hash, recovered_hash);
}

#[test]
fn test_node_identity_workflow() {
    // 1. Create seed
    let seed = random_seed();

    // 2. Derive node identity
    let identity = NodeIdentity::from_seed(&seed).unwrap();

    // 3. Get node ID
    let node_id = identity.node_id();
    assert_eq!(node_id.as_bytes().len(), 33);

    // 4. Sign a message
    let message = b"test message";
    let signature = identity.sign(message).unwrap();
    assert_eq!(signature.len(), 64);
}

#[test]
fn test_invoice_parsing() {
    // Test mainnet invoice
    let mainnet = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";
    let parsed = Bolt11Invoice::parse(mainnet).unwrap();
    assert_eq!(parsed.network(), Network::Mainnet);

    // Test testnet invoice
    let testnet = "lntb1u1p0xxxx";
    let parsed = Bolt11Invoice::parse(testnet).unwrap();
    assert_eq!(parsed.network(), Network::Testnet);
}

#[test]
fn test_invoice_builder() {
    let preimage = PaymentPreimage::random();
    let payment_hash = preimage.payment_hash();

    let data = InvoiceBuilder::new(Network::Mainnet)
        .amount_sats(100_000) // 100k sats
        .description("Test payment")
        .payment_hash(payment_hash)
        .expiry(3600)
        .build()
        .unwrap();

    assert_eq!(data.network, Network::Mainnet);
    assert_eq!(data.amount_msat, Some(100_000_000)); // 100k sats = 100M msat
    assert_eq!(data.description, Some("Test payment".to_string()));
}

#[test]
fn test_channel_point() {
    let txid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let cp = ChannelPoint::from_parts(txid, 0).unwrap();

    assert_eq!(cp.output_index(), 0);

    // Parse from string
    let cp_str = format!("{}:1", txid);
    let cp2 = ChannelPoint::parse(&cp_str).unwrap();
    assert_eq!(cp2.output_index(), 1);
}

#[test]
fn test_short_channel_id() {
    let scid = ShortChannelId::new(700000, 1234, 0);

    assert_eq!(scid.block_height(), 700000);
    assert_eq!(scid.tx_index(), 1234);
    assert_eq!(scid.output_index(), 0);
    assert_eq!(scid.to_string(), "700000x1234x0");

    // Parse from string
    let parsed = ShortChannelId::parse("700000x1234x0").unwrap();
    assert_eq!(scid, parsed);
}

#[test]
fn test_route_hint() {
    let node_id = NodeId::from_bytes([2u8; 33]);
    let scid = ShortChannelId::new(700000, 1, 0);

    let hint = RouteHintBuilder::new()
        .hop(node_id, scid, 1000, 100, 144)
        .build();

    assert_eq!(hint.len(), 1);

    let hop = &hint.hops()[0];
    assert_eq!(hop.fee_base_msat, 1000);
    assert_eq!(hop.cltv_expiry_delta, 144);
}

#[test]
fn test_fee_calculation() {
    let node_id = NodeId::from_bytes([2u8; 33]);
    let scid = ShortChannelId::new(700000, 1, 0);

    let hop = RouteHintHop::new(
        node_id,
        scid,
        1000,  // 1 sat base fee
        1000,  // 0.1% proportional (1000 ppm)
        144,
    );

    // For 1 BTC (100,000,000,000 msat):
    // base: 1000 msat
    // proportional: 100,000,000,000 * 1000 / 1,000,000 = 100,000,000 msat
    // total: 100,001,000 msat
    assert_eq!(hop.fee_for_amount(100_000_000_000), 100_001_000);
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// **Feature: rustywallet-lightning, Property 1: Payment hash is deterministic**
        #[test]
        fn prop_payment_hash_deterministic(bytes in prop::array::uniform32(any::<u8>())) {
            let preimage = PaymentPreimage::from_bytes(bytes);
            let hash1 = preimage.payment_hash();
            let hash2 = preimage.payment_hash();
            prop_assert_eq!(hash1, hash2);
        }

        /// **Feature: rustywallet-lightning, Property 2: Payment hash verification**
        #[test]
        fn prop_payment_hash_verification(bytes in prop::array::uniform32(any::<u8>())) {
            let preimage = PaymentPreimage::from_bytes(bytes);
            let hash = preimage.payment_hash();
            prop_assert!(hash.verify(&preimage));
        }

        /// **Feature: rustywallet-lightning, Property 3: Hex roundtrip for payment hash**
        #[test]
        fn prop_payment_hash_hex_roundtrip(bytes in prop::array::uniform32(any::<u8>())) {
            let hash = PaymentHash::from_bytes(bytes);
            let hex = hash.to_hex();
            let recovered = PaymentHash::from_hex(&hex).unwrap();
            prop_assert_eq!(hash, recovered);
        }

        /// **Feature: rustywallet-lightning, Property 4: Short channel ID encoding**
        #[test]
        fn prop_scid_encoding(
            block in 0u32..0xFFFFFF,
            tx in 0u32..0xFFFFFF,
            output in 0u16..0xFFFF
        ) {
            let scid = ShortChannelId::new(block, tx, output);
            prop_assert_eq!(scid.block_height(), block);
            prop_assert_eq!(scid.tx_index(), tx);
            prop_assert_eq!(scid.output_index(), output);
        }

        /// **Feature: rustywallet-lightning, Property 5: Fee calculation is non-negative**
        #[test]
        fn prop_fee_non_negative(
            base in 0u32..1_000_000,
            proportional in 0u32..1_000_000,
            amount in 0u64..1_000_000_000_000u64
        ) {
            let node_id = NodeId::from_bytes([2u8; 33]);
            let scid = ShortChannelId::new(700000, 1, 0);
            let hop = RouteHintHop::new(node_id, scid, base, proportional, 144);
            let fee = hop.fee_for_amount(amount);
            prop_assert!(fee >= base as u64);
        }
    }
}
