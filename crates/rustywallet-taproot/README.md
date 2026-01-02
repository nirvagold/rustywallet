# rustywallet-taproot

Taproot (BIP340/341/342) implementation for Bitcoin wallet development.

## Features

- **X-only Public Keys (BIP340)**: 32-byte public key representation
- **Schnorr Signatures (BIP340)**: Sign and verify with Schnorr
- **Tagged Hashes**: Domain-separated hashing for BIP340/341
- **Key Tweaking**: Taproot key tweaking with merkle roots
- **TapTree**: Build and manage Taproot script trees
- **Control Blocks**: Script path spending proofs
- **P2TR Addresses**: Generate bech32m addresses
- **Signature Hashes**: BIP341 sighash computation

## Installation

```toml
[dependencies]
rustywallet-taproot = "0.1"
```

## Quick Start

### Key Path Spending

```rust
use rustywallet_taproot::{XOnlyPublicKey, TaprootOutput, Network};
use secp256k1::{Secp256k1, SecretKey};

// Generate internal key
let secp = Secp256k1::new();
let secret_key = SecretKey::new(&mut rand::thread_rng());
let public_key = secret_key.public_key(&secp);
let (xonly, _parity) = public_key.x_only_public_key();
let internal_key = XOnlyPublicKey::from_inner(xonly);

// Create key-path only output
let output = TaprootOutput::key_path_only(internal_key).unwrap();

// Generate P2TR address
let address = output.address(Network::Mainnet).unwrap();
println!("P2TR Address: {}", address); // bc1p...
```

### Schnorr Signing

```rust
use rustywallet_taproot::{schnorr_sign, schnorr_verify, XOnlyPublicKey};
use secp256k1::{Secp256k1, SecretKey};

let secp = Secp256k1::new();
let secret_key = SecretKey::new(&mut rand::thread_rng());
let message = [0x42u8; 32];

// Sign
let signature = schnorr_sign(&secp, &message, &secret_key).unwrap();

// Verify
let public_key = secret_key.public_key(&secp);
let (xonly, _) = public_key.x_only_public_key();
let xonly_key = XOnlyPublicKey::from_inner(xonly);
assert!(schnorr_verify(&secp, &message, &signature, &xonly_key).is_ok());
```

### Script Path Spending

```rust
use rustywallet_taproot::{
    TaprootOutput, TapTree, TapLeaf, ControlBlock, 
    XOnlyPublicKey, Network
};

// Create a script tree with two leaves
let script1 = vec![0x51]; // OP_1
let script2 = vec![0x52]; // OP_2
let tree = rustywallet_taproot::two_leaf_tree(script1.clone(), script2);

// Create output with script tree
let output = TaprootOutput::with_script_tree(internal_key, &tree).unwrap();

// Get control block for spending via script1
let leaf = TapLeaf::new(script1.clone());
let control_block = ControlBlock::for_leaf(
    &tree, 
    &leaf, 
    internal_key, 
    output.parity
).unwrap();

// Verify control block
assert!(control_block.verify(&output.output_key, &script1).unwrap());
```

## API Overview

### Types

| Type | Description |
|------|-------------|
| `XOnlyPublicKey` | 32-byte x-only public key (BIP340) |
| `Parity` | Y-coordinate parity (Even/Odd) |
| `SchnorrSignature` | 64-byte Schnorr signature |
| `TaprootOutput` | Taproot output with spending info |
| `TapTree` | Taproot script tree |
| `TapLeaf` | Single script leaf |
| `ControlBlock` | Script path spending proof |
| `TaprootSighashType` | Signature hash types |

### Functions

| Function | Description |
|----------|-------------|
| `schnorr_sign` | Create Schnorr signature |
| `schnorr_verify` | Verify Schnorr signature |
| `tweak_public_key` | Tweak public key with merkle root |
| `tweak_private_key` | Tweak private key for signing |
| `tagged_hash` | Compute BIP340 tagged hash |
| `parse_address` | Parse P2TR address |
| `create_address` | Create P2TR address |

## BIP Compliance

- **BIP340**: Schnorr Signatures for secp256k1
- **BIP341**: Taproot: SegWit version 1 spending rules
- **BIP342**: Validation of Taproot Scripts

## License

MIT
