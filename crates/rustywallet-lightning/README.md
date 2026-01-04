# rustywallet-lightning

Lightning Network utilities for Bitcoin wallets.

## Features

- **BOLT11 Invoices**: Parse and create Lightning invoices
- **BOLT12 Offers**: Parse and create reusable payment offers
- **Payment Hashes**: Generate and verify payment hashes/preimages
- **Node Identity**: Derive node ID from HD seed
- **Route Hints**: Parse and create route hints for private channels
- **Channel Points**: Handle channel point references

## Installation

```toml
[dependencies]
rustywallet-lightning = "0.2"
```

## Quick Start

### Payment Hash/Preimage

```rust
use rustywallet_lightning::prelude::*;

// Generate a random payment preimage
let preimage = PaymentPreimage::random();

// Compute the payment hash
let payment_hash = preimage.payment_hash();
println!("Payment hash: {}", payment_hash);

// Verify a preimage matches a hash
assert!(payment_hash.verify(&preimage));
```

### BOLT12 Offers

BOLT12 offers provide a more flexible and privacy-preserving way to request payments:

```rust
use rustywallet_lightning::bolt12::{Bolt12Offer, OfferBuilder};

// Create an offer
let offer = OfferBuilder::new()
    .description("Coffee")
    .amount_msats(10_000)  // 10 sats
    .issuer("Bob's Coffee Shop")
    .expires_in(86400 * 30)  // 30 days
    .build()
    .unwrap();

// Encode to string
let encoded = offer.encode();
println!("Offer: {}", encoded);  // lno1...

// Parse an offer
let parsed = Bolt12Offer::parse(&encoded).unwrap();
println!("Description: {}", parsed.description());
println!("Amount: {:?}", parsed.amount());
println!("Issuer: {:?}", parsed.issuer());
```

#### Offer Builder Options

```rust
use rustywallet_lightning::bolt12::OfferBuilder;

let offer = OfferBuilder::new()
    .description("Donation")           // Required
    .amount_msats(50_000)              // Fixed amount (optional)
    .amount_variable()                  // Or variable amount
    .issuer("My Node")                 // Issuer name
    .expires_in(3600)                  // Expiry in seconds
    .quantity_max(10)                  // Max quantity per payment
    .build()
    .unwrap();
```

#### Offer Fields

| Field | Description |
|-------|-------------|
| `description()` | Human-readable description |
| `amount()` | Payment amount (fixed, variable, or currency) |
| `expiry()` | Absolute expiry timestamp |
| `is_expired()` | Check if offer has expired |
| `issuer()` | Issuer name/identifier |
| `node_id()` | Recipient node public key |
| `offer_id()` | Unique offer identifier (hash) |
| `paths()` | Blinded paths for privacy |
| `quantity_max()` | Maximum quantity per payment |

### Parse BOLT11 Invoice

```rust
use rustywallet_lightning::prelude::*;

let invoice = "lnbc1pvjluez..."; // Your invoice string
let parsed = Bolt11Invoice::parse(invoice).unwrap();

println!("Network: {:?}", parsed.network());
println!("Amount: {:?} msat", parsed.amount_msat());
println!("Expired: {}", parsed.is_expired());
```

### Create Invoice Data

```rust
use rustywallet_lightning::prelude::*;

let preimage = PaymentPreimage::random();
let payment_hash = preimage.payment_hash();

let invoice_data = InvoiceBuilder::new(Network::Mainnet)
    .amount_sats(10000)  // 10,000 sats
    .description("Coffee payment")
    .payment_hash(payment_hash)
    .expiry(3600)  // 1 hour
    .build()
    .unwrap();
```

### Node Identity

```rust
use rustywallet_lightning::node::NodeIdentity;
use rustywallet_hd::Seed;

// Derive node identity from seed
let seed = Seed::random();
let identity = NodeIdentity::from_seed(&seed).unwrap();

println!("Node ID: {}", identity.node_id());

// Sign a message
let signature = identity.sign(b"Hello, Lightning!").unwrap();
```

### Channel Points

```rust
use rustywallet_lightning::prelude::*;

// Parse channel point from string
let cp = ChannelPoint::parse(
    "abc123...def456:0"
).unwrap();

println!("TXID: {}", cp.txid_hex());
println!("Output: {}", cp.output_index());

// Short channel ID
let scid = ShortChannelId::new(700000, 1234, 0);
println!("SCID: {}", scid);  // "700000x1234x0"
```

### Route Hints

```rust
use rustywallet_lightning::prelude::*;

let node_id = NodeId::from_bytes([2u8; 33]);
let scid = ShortChannelId::new(700000, 1, 0);

let hint = RouteHintBuilder::new()
    .hop(
        node_id,
        scid,
        1000,  // base fee (msat)
        100,   // proportional fee (ppm)
        144,   // CLTV delta
    )
    .build();

// Calculate routing fee
let hop = &hint.hops()[0];
let fee = hop.fee_for_amount(1_000_000);  // fee for 1M msat
```

## API Reference

### Types

| Type | Description |
|------|-------------|
| `PaymentPreimage` | 32-byte payment secret |
| `PaymentHash` | SHA256 hash of preimage |
| `Bolt11Invoice` | Parsed BOLT11 invoice |
| `Bolt12Offer` | BOLT12 offer for reusable payments |
| `OfferBuilder` | Builder for BOLT12 offers |
| `OfferAmount` | Amount type (fixed, variable, currency) |
| `InvoiceBuilder` | Builder for invoice data |
| `NodeIdentity` | Node keypair derived from seed |
| `NodeId` | 33-byte compressed public key |
| `ChannelPoint` | Funding txid:output reference |
| `ShortChannelId` | Compact block:tx:output ID |
| `RouteHint` | Private channel routing info |
| `RouteHintHop` | Single hop in route hint |
| `BlindedPath` | Blinded path for receiver privacy |

### Networks

- `Network::Mainnet` - Bitcoin mainnet (`lnbc`)
- `Network::Testnet` - Bitcoin testnet (`lntb`)
- `Network::Regtest` - Bitcoin regtest (`lnbcrt`)

## BOLT11 vs BOLT12

| Feature | BOLT11 | BOLT12 |
|---------|--------|--------|
| Reusable | No | Yes |
| Expiry | Required | Optional |
| Privacy | Limited | Blinded paths |
| Amount | Fixed | Fixed/Variable |
| Encoding | Bech32 | Bech32m |
| Prefix | `lnbc` | `lno` |

## Security Notes

- `PaymentPreimage` debug output is redacted
- `NodeIdentity` secret key is redacted in debug
- Use secure random for preimage generation
- BOLT12 offers support blinded paths for receiver privacy

## License

MIT
