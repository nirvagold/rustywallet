# rustywallet 🦀💰

A collection of Rust crates for cryptocurrency wallet utilities with focus on clean Developer Experience (DX) and type-safety.

## Crates

| Crate | Status | Description |
|-------|--------|-------------|
| [rustywallet-keys](./crates/rustywallet-keys) | ✔️ Done | Private & Public key management |
| rustywallet-address | 🔜 Next | Address generation (Bitcoin, Ethereum) |
| rustywallet-mnemonic | 📋 Planned | BIP39 mnemonic/seed phrase |
| rustywallet-hd | 📋 Planned | HD Wallet (BIP32/BIP44) |
| rustywallet-signer | 📋 Planned | Message & transaction signing |

## Quick Start

```rust
use rustywallet_keys::prelude::*;

// Generate a random private key
let private_key = PrivateKey::random();

// Export to various formats
println!("Hex: {}", private_key.to_hex());
println!("WIF: {}", private_key.to_wif(Network::Mainnet));
println!("Decimal: {}", private_key.to_decimal());

// Derive public key
let public_key = private_key.public_key();
println!("Public Key: {}", public_key.to_hex(PublicKeyFormat::Compressed));
```

## Installation

```toml
[dependencies]
rustywallet-keys = "0.1"
```

## Features

### rustywallet-keys
- 🔐 Secure random key generation (CSPRNG)
- 📥 Import from hex, WIF, bytes
- 📤 Export to hex, WIF, decimal, bytes
- 🔑 Public key derivation (compressed/uncompressed)
- 🛡️ Secure memory handling (zeroize on drop)
- ✅ Comprehensive validation

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
