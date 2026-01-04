# Privacy Guide

This guide covers privacy-enhancing features in rustywallet.

## Silent Payments (BIP352)

Silent Payments allow receiving payments without revealing your address on-chain.

### Creating a Silent Payment Address

```rust
use rustywallet_address::silent_payments::{SilentPaymentAddress, SilentPaymentLabel};
use rustywallet_keys::PrivateKey;

// Create from scan and spend keys
let scan_key = PrivateKey::random();
let spend_key = PrivateKey::random();

let address = SilentPaymentAddress::new(
    &scan_key.public_key(),
    &spend_key.public_key(),
    Network::BitcoinMainnet,
)?;

println!("Silent Payment Address: {}", address);  // sp1q...
```

### Scanning for Payments

```rust
use rustywallet_electrum::SilentPaymentScanner;

let scanner = SilentPaymentScanner::new(client, scan_key);

// Scan blocks for payments to your address
let payments = scanner.scan_blocks(800_000, 800_100).await?;

for payment in payments {
    println!("Found payment: {} sats at {}", payment.amount, payment.txid);
    // payment.spending_key can be used to spend the output
}
```

### Labels for Multiple Addresses

```rust
use rustywallet_address::silent_payments::SilentPaymentLabel;

// Create labeled addresses for different purposes
let donation_label = SilentPaymentLabel::new(1);
let invoice_label = SilentPaymentLabel::new(2);

// Scanner can detect which label received the payment
scanner.add_label(donation_label);
scanner.add_label(invoice_label);
```

## CoinJoin

CoinJoin combines multiple users' transactions to break the transaction graph.

### PSBT-Based CoinJoin

```rust
use rustywallet_coinjoin::{PsbtCoinJoinBuilder, CoinJoinInput, CoinJoinOutput};

// Build a CoinJoin transaction
let builder = PsbtCoinJoinBuilder::new()
    .add_input(my_input)
    .add_output(my_output);

let psbt = builder.build_psbt()?;

// Each participant signs their inputs
let signed_psbt = sign_psbt(psbt, &my_key)?;

// Combine all participant PSBTs
let combined = PsbtCoinJoinBuilder::combine_participant_psbts(&[
    signed_psbt_1,
    signed_psbt_2,
    signed_psbt_3,
])?;

// Finalize and broadcast
let tx = PsbtCoinJoinBuilder::finalize(combined)?;
```

### PayJoin (BIP78)

PayJoin is a two-party CoinJoin that looks like a regular transaction.

```rust
use rustywallet_coinjoin::PsbtPayJoin;

// Sender creates initial PSBT
let original_psbt = create_payment_psbt(recipient, amount)?;

// Receiver adds their input (PayJoin proposal)
let payjoin = PsbtPayJoin::new(original_psbt);
let proposal = payjoin.create_proposal(receiver_input)?;

// Sender signs the proposal
let signed = sign_psbt(proposal, &sender_key)?;

// Broadcast
```

## Bloom Filters for Privacy

Use Bloom filters to check addresses without revealing which ones you're interested in.

### Standard Bloom Filter

```rust
use rustywallet_bloom::BloomFilter;

// Create filter with your addresses
let mut filter = BloomFilter::new(1000, 0.01);
for addr in my_addresses {
    filter.insert(&addr);
}

// Check addresses without revealing which ones are yours
for addr in all_addresses {
    if filter.contains(&addr) {
        // Might be one of yours (or false positive)
    }
}
```

### Counting Bloom Filter

Counting filters allow removal, useful for dynamic address sets.

```rust
use rustywallet_bloom::CountingBloomFilter;

let mut filter = CountingBloomFilter::new(1000, 0.01);

// Add addresses
filter.insert("bc1q...");

// Remove when no longer needed
filter.remove("bc1q...")?;
```

## Best Practices

1. **Use Silent Payments** for receiving - addresses are never reused
2. **Use CoinJoin** periodically to break transaction history
3. **Use Tor** when connecting to Electrum servers
4. **Avoid address reuse** - generate new addresses for each transaction
5. **Use Taproot** - all Taproot outputs look the same on-chain
6. **Consider FROST** - threshold signatures hide the number of signers

## Privacy Comparison

| Feature | Privacy Level | Trade-off |
|---------|--------------|-----------|
| Silent Payments | High | Requires scanning |
| CoinJoin | High | Coordination needed |
| PayJoin | Medium | Two-party only |
| Taproot | Medium | Newer, less adoption |
| Bloom Filters | Low | False positives |
