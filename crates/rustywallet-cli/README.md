# rustywallet-cli

[![Crates.io](https://img.shields.io/crates/v/rustywallet-cli.svg)](https://crates.io/crates/rustywallet-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70+-blue.svg)](https://www.rust-lang.org)

A secure, cross-platform command-line tool for cryptocurrency wallet operations supporting Bitcoin, Ethereum, and other blockchain networks.

## Features

- **Private Key Generation**: Generate cryptographically secure private keys in hex or WIF format
- **Mnemonic Support**: Create and validate BIP39 mnemonic phrases (12/15/18/21/24 words)
- **HD Wallet Derivation**: Hierarchical deterministic wallet support with custom derivation paths
- **Multi-Chain Address Generation**: Support for Bitcoin (Legacy, SegWit, Taproot) and Ethereum addresses
- **Message Signing**: Sign messages using Bitcoin (BIP-137) and Ethereum (EIP-191) standards
- **Signature Verification**: Verify message signatures for both Bitcoin and Ethereum
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **Secure**: No network connections, all operations performed locally

## Installation

### From Crates.io

```bash
cargo install rustywallet-cli
```

### From Source

```bash
git clone https://github.com/username/rustywallet-cli
cd rustywallet-cli
cargo install --path .
```

## Commands

### `generate` - Generate Private Keys

Generate cryptographically secure private keys.

```bash
# Generate private key in hex format (default)
rustywallet generate

# Generate private key in WIF format for mainnet
rustywallet generate --format wif --network mainnet

# Generate private key in WIF format for testnet
rustywallet generate --format wif --network testnet
```

**Options:**
- `--format`: Output format (`hex` or `wif`, default: `hex`)
- `--network`: Network for WIF format (`mainnet` or `testnet`, default: `mainnet`)

### `mnemonic` - Mnemonic Operations

Generate and validate BIP39 mnemonic phrases.

```bash
# Generate 12-word mnemonic (default)
rustywallet mnemonic

# Generate 24-word mnemonic
rustywallet mnemonic --words 24

# Generate mnemonic and show seed
rustywallet mnemonic --words 12 --show-seed

# Validate existing mnemonic
rustywallet mnemonic --validate "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Generate with custom entropy length
rustywallet mnemonic --words 15
```

**Options:**
- `--words`: Number of words (12, 15, 18, 21, 24, default: `12`)
- `--show-seed`: Display the seed along with mnemonic
- `--validate`: Validate an existing mnemonic phrase

### `address` - Derive Addresses

Derive cryptocurrency addresses from private keys.

```bash
# Generate SegWit address (default)
rustywallet address --key a1b2c3d4e5f6...

# Generate Legacy P2PKH address
rustywallet address --key a1b2c3d4e5f6... --type legacy

# Generate Taproot address
rustywallet address --key a1b2c3d4e5f6... --type taproot

# Generate Ethereum address
rustywallet address --key a1b2c3d4e5f6... --type ethereum

# Specify network for Bitcoin addresses
rustywallet address --key a1b2c3d4e5f6... --type segwit --network testnet
```

**Options:**
- `--key`: Private key in hex format (required)
- `--type`: Address type (`legacy`, `segwit`, `taproot`, `ethereum`, default: `segwit`)
- `--network`: Network (`mainnet` or `testnet`, default: `mainnet`)

### `hd` - HD Wallet Derivation

Hierarchical deterministic wallet operations using BIP32/BIP44 standards.

```bash
# Default BIP44 Bitcoin path (m/44'/0'/0'/0/0)
rustywallet hd --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Custom derivation path for Ethereum
rustywallet hd --mnemonic "abandon..." --path "m/44'/60'/0'/0/0" --address-type ethereum

# With passphrase protection
rustywallet hd --mnemonic "abandon..." --passphrase "secret123"

# Generate multiple addresses
rustywallet hd --mnemonic "abandon..." --count 5

# Testnet derivation
rustywallet hd --mnemonic "abandon..." --network testnet
```

**Options:**
- `--mnemonic`: BIP39 mnemonic phrase (required)
- `--path`: Derivation path (default: `m/44'/0'/0'/0/0`)
- `--address-type`: Address type (`legacy`, `segwit`, `taproot`, `ethereum`, default: `segwit`)
- `--passphrase`: Optional passphrase for seed generation
- `--count`: Number of addresses to generate (default: `1`)
- `--network`: Network (`mainnet` or `testnet`, default: `mainnet`)

### `sign` - Sign Messages

Sign messages using private keys with different signing standards.

```bash
# Bitcoin message signing (BIP-137)
rustywallet sign --key a1b2c3d4e5f6... --message "Hello Bitcoin" --format bitcoin

# Ethereum personal_sign (EIP-191)
rustywallet sign --key a1b2c3d4e5f6... --message "Hello Ethereum" --format ethereum

# Sign with specific address type for Bitcoin
rustywallet sign --key a1b2c3d4e5f6... --message "Hello" --format bitcoin --address-type legacy
```

**Options:**
- `--key`: Private key in hex format (required)
- `--message`: Message to sign (required)
- `--format`: Signing format (`bitcoin` or `ethereum`, required)
- `--address-type`: Bitcoin address type for signature (`legacy`, `segwit`, `taproot`, default: `segwit`)

### `verify` - Verify Signatures

Verify message signatures against addresses.

```bash
# Verify Bitcoin signature
rustywallet verify --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --message "Hello Bitcoin" --signature "base64signature..." --format bitcoin

# Verify Ethereum signature
rustywallet verify --address 0x742d35Cc6634C0532925a3b8D4C9db96590c4 --message "Hello Ethereum" --signature "0x1234..." --format ethereum
```

**Options:**
- `--address`: Address to verify against (required)
- `--message`: Original message that was signed (required)
- `--signature`: Signature to verify (required)
- `--format`: Signature format (`bitcoin` or `ethereum`, required)

## Examples

### Complete Workflow Example

```bash
# 1. Generate a mnemonic
rustywallet mnemonic --words 12
# Output: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about

# 2. Derive HD wallet addresses
rustywallet hd --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --count 3

# 3. Generate a standalone private key
rustywallet generate --format hex

# 4. Get address from private key
rustywallet address --key a1b2c3d4e5f6789... --type segwit

# 5. Sign a message
rustywallet sign --key a1b2c3d4e5f6789... --message "Hello World" --format bitcoin

# 6. Verify the signature
rustywallet verify --address bc1q... --message "Hello World" --signature "signature..." --format bitcoin
```

### Cross-Chain Operations

```bash
# Bitcoin operations
rustywallet generate --format wif --network mainnet
rustywallet address --key <key> --type taproot
rustywallet sign --key <key> --message "Bitcoin message" --format bitcoin

# Ethereum operations  
rustywallet hd --mnemonic "..." --path "m/44'/60'/0'/0/0" --address-type ethereum
rustywallet sign --key <key> --message "Ethereum message" --format ethereum
```

## Security Notes

- All operations are performed locally without network connections
- Private keys and mnemonics are never stored or transmitted
- Use secure random number generation for all cryptographic operations
- Always verify addresses and signatures before using in production
- Store mnemonics and private keys securely

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.