# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-01-04

### Added
- **PSBT CoinJoin Builder**: New `PsbtCoinJoinBuilder` for building CoinJoin transactions as PSBTs
- **PSBT PayJoin**: New `PsbtPayJoin` for BIP78 PayJoin workflow with PSBT support
- **Combine PSBTs**: `combine_participant_psbts()` function to merge signatures from multiple participants
- **Finalize CoinJoin**: `finalize_coinjoin_psbt()` function with validation that all inputs are signed
- **Property Tests**: Added property-based tests for PSBT merge correctness

### Changed
- Updated dependencies to use rustywallet-psbt v0.2
- Improved documentation with PSBT workflow examples

## [0.1.0] - 2026-01-03

### Added
- Initial release
- PayJoin (BIP78) sender and receiver
- CoinJoin transaction builder
- Equal output amount enforcement
- Output shuffling
- Participant management
- Fee calculation utilities
