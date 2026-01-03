# Changelog

All notable changes to this project will be documented in this file.

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
