# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-01-03

### Added
- MuSig2 partial signature support via `threshold` module
  - `add_musig2_partial_sig()` - Store MuSig2 partial signatures in PSBT proprietary fields
  - `get_musig2_partial_sigs()` - Retrieve MuSig2 partial signatures from PSBT
  - `combine_musig2_psbt()` - Combine PSBTs with MuSig2 partial signatures
  - `count_musig2_partial_sigs()` - Count MuSig2 partial signatures for an input
- FROST threshold signature support
  - `add_frost_partial_sig()` - Store FROST signature shares with signer identifier
  - `get_frost_partial_sigs()` - Retrieve FROST signature shares from PSBT
  - `count_frost_partial_sigs()` - Count FROST partial signatures for an input
- `finalize_threshold_psbt()` - Finalize PSBT with aggregated threshold signatures
- `PsbtMuSig2PartialSig` and `PsbtFrostPartialSig` structs for PSBT storage
- Proprietary field prefixes for MuSig2 ("musig2") and FROST ("frost")
- Property-based tests for partial signature storage and aggregation

### Changed
- Updated dependencies: rustywallet-musig v0.1, rustywallet-frost v0.1

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
