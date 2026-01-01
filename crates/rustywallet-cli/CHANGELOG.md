# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-01-15

### Added
- Initial release of rustywallet-cli
- Private key generation in hex and WIF formats
- BIP39 mnemonic phrase generation and validation (12/15/18/21/24 words)
- HD wallet derivation with BIP32/BIP44 support
- Multi-chain address generation:
  - Bitcoin Legacy (P2PKH) addresses
  - Bitcoin SegWit (P2WPKH) addresses  
  - Bitcoin Taproot (P2TR) addresses
  - Ethereum addresses
- Message signing capabilities:
  - Bitcoin message signing (BIP-137)
  - Ethereum personal_sign (EIP-191)
- Signature verification for Bitcoin and Ethereum
- Cross-platform support (Linux, macOS, Windows)
- Comprehensive CLI with subcommands:
  - `generate` - Generate private keys
  - `mnemonic` - Mnemonic operations
  - `address` - Derive addresses from keys
  - `hd` - HD wallet derivation
  - `sign` - Sign messages
  - `verify` - Verify signatures
- Network support for mainnet and testnet
- Custom derivation path support
- Passphrase protection for HD wallets
- Secure local-only operations (no network connections)

[Unreleased]: https://github.com/username/rustywallet-cli/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/username/rustywallet-cli/releases/tag/v0.1.0