# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-01-03

### Added
- Initial release
- BIP174 (PSBT v0) support
- BIP370 (PSBT v2) support
- Parse PSBT from bytes and base64
- Create PSBT from unsigned transaction
- Update inputs with UTXO info, scripts, BIP32 derivation
- Sign PSBTs with private keys
- Support for P2PKH, P2WPKH, P2SH-P2WPKH inputs
- Support for P2SH, P2WSH, P2SH-P2WSH multisig inputs
- Support for P2TR key path signing
- Combine PSBTs from multiple signers
- Finalize PSBTs and extract signed transactions
- Comprehensive error handling
- Full documentation with examples
