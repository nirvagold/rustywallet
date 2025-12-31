# Design Document: rustywallet-keys

## Overview

**rustywallet-keys** adalah Rust crate yang menyediakan abstraksi type-safe untuk manajemen private key dan public key cryptocurrency. Crate ini menggunakan library `secp256k1` yang sudah battle-tested sebagai backend kriptografi, sambil menyediakan API yang lebih ergonomis dan developer-friendly.

### Design Goals

1. **Type Safety**: Gunakan Rust's type system untuk mencegah kesalahan pada compile time
2. **Zero-Copy Where Possible**: Minimize memory allocations untuk performa optimal
3. **Secure by Default**: Private keys di-mask saat debug, zeroize on drop
4. **Minimal Dependencies**: Hanya depend pada crates yang essential dan well-maintained
5. **Ergonomic API**: Method chaining, builder patterns, dan intuitive naming

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    rustywallet-keys                         │
├─────────────────────────────────────────────────────────────┤
│  pub mod prelude    (convenient re-exports)                 │
├─────────────────────────────────────────────────────────────┤
│  pub mod private_key                                        │
│    ├── PrivateKey (struct)                                  │
│    ├── PrivateKeyError (enum)                               │
│    └── impl: new, random, from_*, to_*, validate            │
├─────────────────────────────────────────────────────────────┤
│  pub mod public_key                                         │
│    ├── PublicKey (struct)                                   │
│    ├── PublicKeyFormat (enum)                               │
│    ├── PublicKeyError (enum)                                │
│    └── impl: from_private_key, compress, uncompress, to_*   │
├─────────────────────────────────────────────────────────────┤
│  pub mod error                                              │
│    └── KeyError (unified error type)                        │
├─────────────────────────────────────────────────────────────┤
│  pub mod network                                            │
│    └── Network (enum: Mainnet, Testnet)                     │
├─────────────────────────────────────────────────────────────┤
│  internal mod encoding                                      │
│    ├── hex (encode/decode)                                  │
│    ├── wif (encode/decode)                                  │
│    └── base58check                                          │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              External Dependencies                          │
├─────────────────────────────────────────────────────────────┤
│  secp256k1    - Elliptic curve operations                   │
│  rand         - Cryptographically secure RNG                │
│  zeroize      - Secure memory clearing                      │
│  thiserror    - Error derive macros                         │
│  bs58         - Base58 encoding                             │
└─────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### PrivateKey

```rust
/// A secp256k1 private key with secure memory handling
pub struct PrivateKey {
    inner: secp256k1::SecretKey,
}

impl PrivateKey {
    /// Generate a new random private key
    pub fn random() -> Self;
    
    /// Create from 32-byte array
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PrivateKeyError>;
    
    /// Create from hex string (64 chars)
    pub fn from_hex(hex: &str) -> Result<Self, PrivateKeyError>;
    
    /// Create from WIF string
    pub fn from_wif(wif: &str) -> Result<Self, PrivateKeyError>;
    
    /// Export as 32-byte array
    pub fn to_bytes(&self) -> [u8; 32];
    
    /// Export as hex string
    pub fn to_hex(&self) -> String;
    
    /// Export as WIF string
    pub fn to_wif(&self, network: Network) -> String;
    
    /// Derive the corresponding public key
    pub fn public_key(&self) -> PublicKey;
    
    /// Validate if bytes represent a valid private key
    pub fn is_valid(bytes: &[u8; 32]) -> bool;
}

impl Drop for PrivateKey {
    // Zeroize memory on drop
}

impl Debug for PrivateKey {
    // Masked output: PrivateKey(****)
}
```

### PublicKey

```rust
/// A secp256k1 public key
pub struct PublicKey {
    inner: secp256k1::PublicKey,
}

/// Public key serialization format
pub enum PublicKeyFormat {
    Compressed,    // 33 bytes
    Uncompressed,  // 65 bytes
}

impl PublicKey {
    /// Create from private key
    pub fn from_private_key(private_key: &PrivateKey) -> Self;
    
    /// Create from compressed bytes (33 bytes)
    pub fn from_compressed(bytes: &[u8; 33]) -> Result<Self, PublicKeyError>;
    
    /// Create from uncompressed bytes (65 bytes)
    pub fn from_uncompressed(bytes: &[u8; 65]) -> Result<Self, PublicKeyError>;
    
    /// Create from hex string
    pub fn from_hex(hex: &str) -> Result<Self, PublicKeyError>;
    
    /// Export as compressed bytes
    pub fn to_compressed(&self) -> [u8; 33];
    
    /// Export as uncompressed bytes
    pub fn to_uncompressed(&self) -> [u8; 65];
    
    /// Export as hex string
    pub fn to_hex(&self, format: PublicKeyFormat) -> String;
    
    /// Export as bytes with specified format
    pub fn to_bytes(&self, format: PublicKeyFormat) -> Vec<u8>;
}
```

### Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum PrivateKeyError {
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
    
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),
    
    #[error("Invalid WIF format: {0}")]
    InvalidWif(String),
    
    #[error("Key out of range: must be between 1 and curve order - 1")]
    OutOfRange,
    
    #[error("Invalid checksum in WIF")]
    InvalidChecksum,
}

#[derive(Debug, thiserror::Error)]
pub enum PublicKeyError {
    #[error("Invalid key length: expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),
    
    #[error("Invalid public key point")]
    InvalidPoint,
}

/// Unified error type for the crate
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error(transparent)]
    PrivateKey(#[from] PrivateKeyError),
    
    #[error(transparent)]
    PublicKey(#[from] PublicKeyError),
}
```

### Network

```rust
/// Blockchain network type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Bitcoin Mainnet (WIF prefix: 0x80)
    Mainnet,
    /// Bitcoin Testnet (WIF prefix: 0xEF)
    Testnet,
}

impl Network {
    pub fn wif_version_byte(&self) -> u8 {
        match self {
            Network::Mainnet => 0x80,
            Network::Testnet => 0xEF,
        }
    }
}
```

### Prelude Module

```rust
pub mod prelude {
    pub use crate::private_key::PrivateKey;
    pub use crate::public_key::{PublicKey, PublicKeyFormat};
    pub use crate::network::Network;
    pub use crate::error::{KeyError, PrivateKeyError, PublicKeyError};
}
```

## Data Models

### Internal Encoding Module

```rust
// internal, not exposed publicly
mod encoding {
    pub mod hex {
        pub fn encode(bytes: &[u8]) -> String;
        pub fn decode(hex: &str) -> Result<Vec<u8>, HexError>;
    }
    
    pub mod wif {
        pub fn encode(key: &[u8; 32], network: Network, compressed: bool) -> String;
        pub fn decode(wif: &str) -> Result<([u8; 32], Network, bool), WifError>;
    }
    
    pub mod base58check {
        pub fn encode(data: &[u8]) -> String;
        pub fn decode(encoded: &str) -> Result<Vec<u8>, Base58Error>;
    }
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Random Key Validity
*For any* randomly generated private key, the key SHALL be valid (non-zero and less than the secp256k1 curve order).
**Validates: Requirements 1.1, 1.2**

### Property 2: Hex Round-Trip
*For any* valid private key, converting to hex and parsing back SHALL produce an equivalent private key.
**Validates: Requirements 2.1, 3.1, 3.5**

### Property 3: Bytes Round-Trip
*For any* valid private key, exporting to bytes and importing back SHALL produce an equivalent private key.
**Validates: Requirements 2.2, 3.2, 3.5**

### Property 4: WIF Round-Trip
*For any* valid private key and network, encoding to WIF and decoding back SHALL produce an equivalent private key.
**Validates: Requirements 2.3, 3.3, 3.4, 3.5**

### Property 5: Hex Case Insensitivity
*For any* valid hex string representing a private key, both uppercase and lowercase versions SHALL parse to equivalent keys.
**Validates: Requirements 2.5**

### Property 6: Invalid Input Rejection
*For any* byte array that is zero or >= curve order, the validation function SHALL return false and construction SHALL return an error.
**Validates: Requirements 2.4, 4.1, 4.2, 4.3**

### Property 7: Public Key Derivation Determinism
*For any* private key, deriving the public key multiple times SHALL produce identical results.
**Validates: Requirements 5.4**

### Property 8: Public Key Format Invariants
*For any* private key, the derived compressed public key SHALL be 33 bytes and uncompressed SHALL be 65 bytes.
**Validates: Requirements 5.2, 5.3, 7.1, 7.2**

### Property 9: Public Key Format Round-Trip
*For any* public key, converting between compressed and uncompressed formats SHALL preserve the underlying key data.
**Validates: Requirements 6.1, 6.2, 6.3, 6.4**

### Property 10: Public Key Serialization Round-Trip
*For any* public key, serializing to bytes/hex and deserializing back SHALL produce an equivalent public key.
**Validates: Requirements 7.3**

### Property 11: Debug Output Security
*For any* private key, the Debug trait output SHALL NOT contain the actual key bytes in hex or any recognizable format.
**Validates: Requirements 8.5**



## Error Handling

### Error Strategy

1. **Result-based**: All fallible operations return `Result<T, E>`
2. **Specific errors**: Each error type has variants for specific failure modes
3. **Error conversion**: Implement `From` traits for seamless error propagation
4. **No panics**: Library code never panics on invalid input

### Error Propagation

```rust
// User code example
fn process_key(hex: &str) -> Result<PublicKey, KeyError> {
    let private_key = PrivateKey::from_hex(hex)?;  // PrivateKeyError -> KeyError
    Ok(private_key.public_key())
}
```

## Testing Strategy

### Property-Based Testing

The crate will use **proptest** for property-based testing. Each correctness property will be implemented as a proptest.

Configuration:
- Minimum 100 iterations per property test
- Custom generators for valid private keys (1 to curve_order - 1)
- Edge case generators for boundary values

### Unit Tests

Unit tests will cover:
- Known test vectors from BIP standards
- Edge cases (zero key, max key, boundary values)
- Error conditions and error messages

### Test Organization

```
tests/
├── property_tests.rs    # All property-based tests
├── test_vectors.rs      # Known test vectors
└── edge_cases.rs        # Edge case unit tests
```

## Dependencies

```toml
[dependencies]
secp256k1 = { version = "0.29", features = ["rand"] }
rand = "0.8"
zeroize = { version = "1.8", features = ["derive"] }
thiserror = "1.0"
bs58 = "0.5"

[dev-dependencies]
proptest = "1.5"
```

## Security Considerations

1. **Memory Zeroization**: Private keys are zeroized when dropped using the `zeroize` crate
2. **Constant-time operations**: Use secp256k1's constant-time implementations
3. **No logging**: Private key values are never logged or printed
4. **Debug masking**: Debug trait shows `PrivateKey(****)` instead of actual value
