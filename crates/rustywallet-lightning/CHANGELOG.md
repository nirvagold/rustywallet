# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-01-04

### Added

- **BOLT12 Offers** support for reusable payment requests
  - `Bolt12Offer` struct for parsing and encoding offers
  - `OfferBuilder` for creating offers with fluent API
  - `OfferAmount` enum for fixed, variable, and currency amounts
  - `BlindedPath` struct for receiver privacy
  - Parse offers from `lno1...` strings
  - Encode offers to bech32m format
  - Support for description, amount, expiry, issuer fields
  - Offer ID computation (SHA256 hash)
  - Signature validation support
  - Bitcoin mainnet chain detection
  - Quantity limits for offers
- Property-based tests for BOLT12 offer round-trip (Property 20)
- Updated prelude with BOLT12 exports
- Enhanced documentation with BOLT12 examples

### Changed

- Updated to version 0.2.0
- Added "bolt12" and "offer" to package keywords

## [0.1.0] - 2026-01-03

### Added

- Initial release
- `PaymentPreimage` and `PaymentHash` types for payment handling
- `Bolt11Invoice` parser for Lightning invoices
- `InvoiceBuilder` for creating invoice data
- `NodeIdentity` for deriving node ID from HD seed
- `NodeId` type for 33-byte compressed public keys
- `ChannelPoint` for funding transaction references
- `ShortChannelId` for compact channel identifiers
- `RouteHint` and `RouteHintHop` for private channel routing
- `RouteHintBuilder` for constructing route hints
- Network support: Mainnet, Testnet, Regtest
- Prelude module for convenient imports
- Comprehensive test suite with property-based tests
