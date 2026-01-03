# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-01-03

### Added

- Initial release
- `KeyAggContext` for BIP327 key aggregation
- `SecretNonce` and `PublicNonce` for secure nonce handling
- `AggregatedNonce` for nonce aggregation
- `PartialSignature` for partial signature creation
- `SchnorrSignature` for complete 64-byte signatures
- `AdaptorSignature` for atomic swaps and adaptor protocols
- `SigningSession` for high-level session management
- Nonce reuse prevention with automatic marking
- Secret value zeroization on drop
- Tagged hash functions (BIP340/BIP327)
- Comprehensive test suite with property-based tests
