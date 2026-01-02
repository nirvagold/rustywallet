# Key Management Guide

This guide covers everything about private and public key handling.

## Private Keys

### Generation

```rust
use rustywallet_keys::prelude::*;

// Random key (cryptographically secure)
let key = PrivateKey::random();

// From 32 bytes
let bytes = [0u8; 32];  // Your bytes
let key = PrivateKey::from_bytes(&bytes)?;

// From hex string
let key = PrivateKey::from_hex("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")?;

// From WIF
let key = PrivateKey::from_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")?;

// From decimal string
let key = PrivateKey::from_decimal("12345678901234567890")?;
```

### Export Formats

```rust
// To bytes (32 bytes)
let bytes: [u8; 32] = key.to_bytes();

// To hex (64 characters)
let hex: String = key.to_hex();

// To WIF (Wallet Import Format)
let wif = key.to_wif(Network::Mainnet);  // Compressed
let wif_uncompressed = key.to_wif_uncompressed(Network::Mainnet);

// To decimal
let decimal = key.to_decimal();
```

### WIF Format Explained

WIF (Wallet Import Format) is the standard way to represent private keys:

| Network | Compressed | Prefix | Example |
|---------|------------|--------|---------|
| Mainnet | Yes | K or L | `KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn` |
| Mainnet | No | 5 | `5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ` |
| Testnet | Yes | c | `cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA` |
| Testnet | No | 9 | `91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgwmaKkrx` |

```rust
// Detect network and compression from WIF
let key = PrivateKey::from_wif("KwDiBf89...")?;
// This is mainnet, compressed
```

## Public Keys

### Derivation

```rust
let private_key = PrivateKey::random();
let public_key = private_key.public_key();
```

### Formats

```rust
// Compressed (33 bytes) - recommended
let compressed: [u8; 33] = public_key.to_compressed();

// Uncompressed (65 bytes) - legacy
let uncompressed: [u8; 65] = public_key.to_uncompressed();

// Hex strings
let hex_compressed = public_key.to_hex_compressed();    // 66 chars
let hex_uncompressed = public_key.to_hex_uncompressed(); // 130 chars
```

### Compressed vs Uncompressed

| Type | Size | Prefix | Use Case |
|------|------|--------|----------|
| Compressed | 33 bytes | 02 or 03 | Modern wallets, SegWit |
| Uncompressed | 65 bytes | 04 | Legacy compatibility |

```rust
// Compressed starts with 02 or 03
// 02 = y-coordinate is even
// 03 = y-coordinate is odd
let compressed = public_key.to_compressed();
assert!(compressed[0] == 0x02 || compressed[0] == 0x03);

// Uncompressed starts with 04
let uncompressed = public_key.to_uncompressed();
assert_eq!(uncompressed[0], 0x04);
```

## Security Best Practices

### 1. Zeroize Sensitive Data

rustywallet automatically zeroizes private keys when dropped:

```rust
{
    let key = PrivateKey::random();
    // Use key...
} // key is zeroized here
```

### 2. Never Log Private Keys

```rust
// BAD - Don't do this!
println!("Key: {}", key.to_hex());

// GOOD - Log only public info
println!("Address: {}", address);
```

### 3. Use Secure Random Generation

```rust
// GOOD - Uses OS CSPRNG
let key = PrivateKey::random();

// BAD - Don't use predictable sources
let bad_key = PrivateKey::from_bytes(&[1u8; 32])?;  // Predictable!
```

### 4. Validate Imported Keys

```rust
use rustywallet_import::import_any;

match import_any(user_input) {
    Ok(key) => {
        // Valid key
    }
    Err(e) => {
        // Invalid input - handle error
        eprintln!("Invalid key: {}", e);
    }
}
```

### 5. Use Strong Passphrases for BIP38

```rust
use rustywallet_export::export_bip38;

// GOOD - Strong passphrase
let encrypted = export_bip38(&key, "correct-horse-battery-staple", Network::Mainnet)?;

// BAD - Weak passphrase
let encrypted = export_bip38(&key, "password123", Network::Mainnet)?;
```

## Key Validation

### Check if Key is Valid

```rust
// Private key must be in range [1, n-1] where n is the curve order
let result = PrivateKey::from_hex("0000...0000");  // Zero - invalid
assert!(result.is_err());

let result = PrivateKey::from_hex("FFFF...FFFF");  // Too large - invalid
assert!(result.is_err());
```

### Verify Public Key Derivation

```rust
let private_key = PrivateKey::from_hex("...")?;
let public_key = private_key.public_key();

// Verify the public key is on the curve
let compressed = public_key.to_compressed();
assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
```

## Common Patterns

### Generate Multiple Keys

```rust
let keys: Vec<PrivateKey> = (0..10)
    .map(|_| PrivateKey::random())
    .collect();
```

### Key Pair Struct

```rust
struct KeyPair {
    private_key: PrivateKey,
    public_key: PublicKey,
    address: String,
}

impl KeyPair {
    fn new(network: Network) -> Result<Self, Error> {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        let address = Address::p2wpkh(&public_key, network)?.to_string();
        
        Ok(Self { private_key, public_key, address })
    }
}
```

### Batch Key Generation

For generating millions of keys, use `rustywallet-batch`:

```rust
use rustywallet_batch::FastKeyGenerator;

let generator = FastKeyGenerator::new();
for key in generator.take(1_000_000) {
    // Process at 7M+ keys/sec
}
```

## Next Steps

- [Address Generation](./address-generation.md)
- [HD Wallets](./hd-wallets.md)
- [Security Best Practices](../advanced/security.md)
