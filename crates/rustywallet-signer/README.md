# rustywallet-signer

[![Crates.io](https://img.shields.io/crates/v/rustywallet-signer.svg)](https://crates.io/crates/rustywallet-signer)
[![Documentation](https://docs.rs/rustywallet-signer/badge.svg)](https://docs.rs/rustywallet-signer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/rustywallet/rustywallet-signer/workflows/CI/badge.svg)](https://github.com/rustywallet/rustywallet-signer/actions)

ECDSA and Schnorr message signing and verification for Bitcoin and Ethereum using secp256k1.

## Features

- **Cross-platform compatibility** - Works on all major platforms
- **BIP340 Schnorr signatures** - Modern Taproot-compatible signing
- **Bitcoin message signing** - BIP-137 compatible message signatures
- **Ethereum personal_sign** - EIP-191 compatible signatures for web3
- **Recoverable signatures** - Extract public keys from signatures
- **Deterministic signing** - RFC 6979 compliant nonce generation
- **Signature verification** - Verify signatures against public keys or addresses
- **Security focused** - Constant-time operations, no secret leakage
- **Zero-copy operations** - Efficient memory usage

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rustywallet-signer = "0.2"
rustywallet-keys = "0.1"
```

## Quick Start

### ECDSA Signing

```rust
use rustywallet_keys::private_key::PrivateKey;
use rustywallet_signer::prelude::*;
use sha2::{Sha256, Digest};

// Generate a private key
let private_key = PrivateKey::random();
let public_key = private_key.public_key();

// Sign a message hash
let message = b"Hello, World!";
let hash: [u8; 32] = Sha256::digest(message).into();
let signature = sign(&private_key, &hash)?;

// Verify the signature
assert!(verify(&public_key, &hash, &signature));
```

### Schnorr Signing (BIP340)

```rust
use rustywallet_keys::private_key::PrivateKey;
use rustywallet_signer::schnorr::{SchnorrSigner, SchnorrVerifier};
use sha2::{Sha256, Digest};

// Generate a private key
let private_key = PrivateKey::random();

// Sign a message hash with Schnorr
let message = b"Hello, Taproot!";
let hash: [u8; 32] = Sha256::digest(message).into();
let signature = private_key.sign_schnorr(&hash)?;

// Get x-only public key and verify
let xonly_pubkey = private_key.x_only_public_key();
assert!(xonly_pubkey.verify_schnorr(&signature, &hash));
```

## Schnorr Signatures (BIP340)

Schnorr signatures are used in Bitcoin's Taproot upgrade and provide several advantages:
- Smaller signatures (64 bytes vs 71-72 for ECDSA)
- Linear signature aggregation (enables MuSig2)
- Provable security under standard assumptions

### Using the SchnorrSigner Trait

```rust
use rustywallet_keys::private_key::PrivateKey;
use rustywallet_signer::schnorr::{SchnorrSigner, SchnorrVerifier};
use sha2::{Sha256, Digest};

let key = PrivateKey::random();
let hash: [u8; 32] = Sha256::digest(b"message").into();

// Sign using the trait
let signature = key.sign_schnorr(&hash)?;

// Sign with auxiliary randomness for extra security
let aux_rand = [0x42u8; 32];
let signature_with_aux = key.sign_schnorr_with_aux(&hash, &aux_rand)?;

// Verify using the trait
let xonly = key.x_only_public_key();
assert!(xonly.verify_schnorr(&signature, &hash));
```

### Using Convenience Functions

```rust
use rustywallet_keys::private_key::PrivateKey;
use rustywallet_signer::schnorr::{sign_schnorr, verify_schnorr, SchnorrSigner};
use sha2::{Sha256, Digest};

let key = PrivateKey::random();
let hash: [u8; 32] = Sha256::digest(b"message").into();

// Sign using convenience function
let signature = sign_schnorr(&key, &hash)?;

// Verify using convenience function
let xonly = key.x_only_public_key();
assert!(verify_schnorr(&xonly, &signature, &hash));
```

## Message Signing

### Bitcoin Message Signing

Sign messages compatible with Bitcoin Core's `signmessage` RPC:

```rust
use rustywallet_keys::private_key::PrivateKey;
use rustywallet_signer::bitcoin::{sign_bitcoin_message, verify_bitcoin_message};

let private_key = PrivateKey::random();
let message = "Hello Bitcoin!";

// Sign the message
let signature = sign_bitcoin_message(&private_key, message)?;
println!("Signature: {}", signature);

// Verify with Bitcoin address
let address = private_key.to_bitcoin_address();
assert!(verify_bitcoin_message(&address, message, &signature)?);
```

### Ethereum Personal Sign

Sign messages compatible with MetaMask and web3.js `personal_sign`:

```rust
use rustywallet_keys::private_key::PrivateKey;
use rustywallet_signer::ethereum::{
    sign_ethereum_message, verify_ethereum_message, 
    public_key_to_address, format_address
};

let private_key = PrivateKey::random();
let message = b"Hello Ethereum!";

// Sign the message
let signature = sign_ethereum_message(&private_key, message)?;
println!("Signature: {}", signature.to_ethereum_hex());

// Get Ethereum address
let address = public_key_to_address(&private_key.public_key());
println!("Address: {}", format_address(&address));

// Verify the signature
assert!(verify_ethereum_message(&address, message, &signature)?);
```

## Signature Verification

### Verify Against Public Key

```rust
use rustywallet_signer::{sign, verify};
use sha2::{Sha256, Digest};

let private_key = PrivateKey::random();
let public_key = private_key.public_key();
let hash: [u8; 32] = Sha256::digest(b"message").into();

let signature = sign(&private_key, &hash)?;
assert!(verify(&public_key, &hash, &signature));
```

### Verify Bitcoin Messages

```rust
use rustywallet_signer::bitcoin::verify_bitcoin_message;

let address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
let message = "Hello Bitcoin!";
let signature = "base64_signature_here";

let is_valid = verify_bitcoin_message(address, message, signature)?;
```

### Verify Ethereum Messages

```rust
use rustywallet_signer::ethereum::verify_ethereum_message;

let address = [0u8; 20]; // 20-byte Ethereum address
let message = b"Hello Ethereum!";
let signature_hex = "0x1234..."; // 65-byte hex signature

let signature = EthereumSignature::from_hex(signature_hex)?;
let is_valid = verify_ethereum_message(&address, message, &signature)?;
```

## Recoverable Signatures

Extract public keys from signatures without prior knowledge:

```rust
use rustywallet_signer::{sign_recoverable, recover_public_key};
use sha2::{Sha256, Digest};

let private_key = PrivateKey::random();
let original_pubkey = private_key.public_key();
let hash: [u8; 32] = Sha256::digest(b"recoverable message").into();

// Create recoverable signature
let recoverable_sig = sign_recoverable(&private_key, &hash)?;

// Recover the public key
let recovered_pubkey = recover_public_key(&recoverable_sig, &hash)?;

assert_eq!(original_pubkey.to_compressed(), recovered_pubkey.to_compressed());
```

### Recover Ethereum Address

```rust
use rustywallet_signer::ethereum::{sign_ethereum_message, recover_ethereum_address};

let private_key = PrivateKey::random();
let message = b"Recover my address";

let signature = sign_ethereum_message(&private_key, message)?;
let recovered_address = recover_ethereum_address(&signature, message)?;

let expected_address = public_key_to_address(&private_key.public_key());
assert_eq!(recovered_address, expected_address);
```

## API Reference

### Core Signing Functions

```rust
// Sign a 32-byte hash with ECDSA
pub fn sign(private_key: &PrivateKey, message_hash: &[u8; 32]) -> Result<Signature>;

// Sign with recovery information
pub fn sign_recoverable(private_key: &PrivateKey, message_hash: &[u8; 32]) -> Result<RecoverableSignature>;

// Verify a signature against a public key
pub fn verify(public_key: &PublicKey, message_hash: &[u8; 32], signature: &Signature) -> bool;

// Recover public key from signature
pub fn recover_public_key(signature: &RecoverableSignature, message_hash: &[u8; 32]) -> Result<PublicKey>;
```

### Schnorr Module (BIP340)

```rust
// SchnorrSigner trait - implemented for PrivateKey
pub trait SchnorrSigner {
    fn sign_schnorr(&self, message_hash: &[u8; 32]) -> Result<SchnorrSignature>;
    fn sign_schnorr_with_aux(&self, message_hash: &[u8; 32], aux_rand: &[u8; 32]) -> Result<SchnorrSignature>;
    fn x_only_public_key(&self) -> XOnlyPublicKey;
}

// SchnorrVerifier trait - implemented for XOnlyPublicKey
pub trait SchnorrVerifier {
    fn verify_schnorr(&self, signature: &SchnorrSignature, message_hash: &[u8; 32]) -> bool;
}

// Convenience functions
pub fn sign_schnorr(private_key: &PrivateKey, message_hash: &[u8; 32]) -> Result<SchnorrSignature>;
pub fn verify_schnorr(pubkey: &XOnlyPublicKey, signature: &SchnorrSignature, message_hash: &[u8; 32]) -> bool;
```

### Bitcoin Module

```rust
// Sign a Bitcoin message (BIP-137)
pub fn sign_bitcoin_message(private_key: &PrivateKey, message: &str) -> Result<String>;

// Verify a Bitcoin message signature
pub fn verify_bitcoin_message(address: &str, message: &str, signature: &str) -> Result<bool>;

// Create Bitcoin message hash
pub fn bitcoin_message_hash(message: &str) -> [u8; 32];
```

### Ethereum Module

```rust
// Sign an Ethereum personal message (EIP-191)
pub fn sign_ethereum_message(private_key: &PrivateKey, message: &[u8]) -> Result<EthereumSignature>;

// Verify an Ethereum message signature
pub fn verify_ethereum_message(address: &[u8; 20], message: &[u8], signature: &EthereumSignature) -> Result<bool>;

// Recover address from signature
pub fn recover_ethereum_address(signature: &EthereumSignature, message: &[u8]) -> Result<[u8; 20]>;

// Convert public key to Ethereum address
pub fn public_key_to_address(public_key: &PublicKey) -> [u8; 20];

// Format address with EIP-55 checksum
pub fn format_address(address: &[u8; 20]) -> String;

// Create Ethereum message hash
pub fn ethereum_message_hash(message: &[u8]) -> [u8; 32];
```

### Types

```rust
// Standard ECDSA signature (64 bytes: r + s)
pub struct Signature { /* ... */ }

// Recoverable signature (65 bytes: r + s + recovery_id)
pub struct RecoverableSignature { /* ... */ }

// Ethereum-specific signature with v, r, s components
pub struct EthereumSignature { /* ... */ }

// BIP340 Schnorr signature (64 bytes)
pub struct SchnorrSignature { /* ... */ }

// X-only public key for Schnorr (32 bytes)
pub struct XOnlyPublicKey { /* ... */ }
```

## Error Handling

All signing operations return `Result<T, SignerError>`:

```rust
use rustywallet_signer::{SignerError, sign};

match sign(&private_key, &hash) {
    Ok(signature) => println!("Signed successfully"),
    Err(SignerError::InvalidPrivateKey) => eprintln!("Invalid private key"),
    Err(SignerError::SigningFailed) => eprintln!("Signing operation failed"),
    Err(e) => eprintln!("Other error: {}", e),
}
```

## Security Considerations

- **Deterministic signatures**: Uses RFC 6979 for secure, deterministic nonce generation
- **Constant-time operations**: All cryptographic operations use constant-time implementations
- **No secret leakage**: Error messages never contain private key material
- **Memory safety**: Built on Rust's memory safety guarantees
- **Audited dependencies**: Uses the well-audited `secp256k1` crate

## Performance

- Zero-allocation signing and verification for pre-hashed messages
- Batch verification support for multiple signatures
- Optimized for both single operations and high-throughput scenarios

## Examples

See the `examples/` directory for complete working examples:

- `basic_signing.rs` - Basic ECDSA signing and verification
- `bitcoin_messages.rs` - Bitcoin message signing workflow
- `ethereum_messages.rs` - Ethereum personal_sign implementation
- `signature_recovery.rs` - Public key recovery examples

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.