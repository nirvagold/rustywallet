# rustywallet-silent

Silent Payments (BIP352) implementation for rustywallet.

## Overview

Silent Payments allow receivers to publish a single static address while each payment generates a unique on-chain address that only the receiver can detect and spend. This provides significant privacy benefits compared to address reuse.

## Features

- **Silent Payment Address**: Generate and parse sp1/tsp1 addresses
- **Payment Derivation**: ECDH-based output key derivation
- **Scanning**: Detect incoming payments to your silent payment address
- **Sending**: Create outputs for silent payment recipients
- **Labels**: Support for multiple labeled addresses from single key
- **Change Handling**: Proper change output derivation

## Usage

```rust
use rustywallet_silent::prelude::*;
use rustywallet_keys::prelude::PrivateKey;

// Generate Silent Payment keys
let scan_key = PrivateKey::random();
let spend_key = PrivateKey::random();

// Create Silent Payment address
let sp_address = SilentPaymentAddress::new(
    &scan_key.public_key(),
    &spend_key.public_key(),
    Network::Mainnet,
).unwrap();

println!("Silent Payment Address: {}", sp_address);

// Sender: Create payment output
let sender_keys = vec![PrivateKey::random()];
let outpoints = vec![([0u8; 32], 0u32)];

let outputs = create_outputs(
    &sender_keys,
    &outpoints,
    &[sp_address.clone()],
).unwrap();

// Receiver: Scan for payments
let scanner = SilentPaymentScanner::new(&scan_key, &spend_key.public_key());
let found = scanner.scan_outputs(&outputs, &outpoints).unwrap();
```

## Protocol Overview

### Address Format

Silent Payment addresses use bech32m encoding:
- Mainnet: `sp1...`
- Testnet: `tsp1...`

The address contains two public keys:
- **Scan key (B_scan)**: Used to detect incoming payments
- **Spend key (B_spend)**: Used to derive spending keys

### Sending

1. Collect all input private keys
2. Compute input hash from outpoints
3. For each recipient, compute shared secret via ECDH
4. Derive output public key: P_output = B_spend + hash(shared_secret || n) * G

### Receiving

1. For each transaction output, compute potential shared secret
2. Check if output matches derived key
3. If match found, compute spending private key

## Security Considerations

- Scan key can be shared with a light client for detection
- Spend key must remain secret
- Each payment creates a unique address (no address reuse)
- Labels allow multiple addresses without additional keys

## License

MIT
