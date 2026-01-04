# Changelog

## [0.2.0] - 2026-01-04

### Added
- Descriptor export with `export_descriptor()`, `export_pubkey_descriptor()`
- `export_multisig_descriptor()` for multi-signature descriptors
- `export_wrapped_multisig_descriptor()` for wsh/sh wrapped multisig
- `export_descriptor_with_metadata()` for full metadata export
- `DescriptorType` enum (Pk, Pkh, Wpkh, ShWpkh, Tr)
- `DescriptorOptions` for configuring export behavior
- `DescriptorExport` struct with descriptor metadata
- `compute_checksum()` and `add_checksum()` helper functions
- PSBT export functionality:
  - `export_psbt()` for base64 export
  - `export_psbt_json()` for JSON export
  - `export_psbt_for_file()` for file storage
  - `export_descriptor_with_psbts()` for bundled export
- `PsbtExport`, `PsbtMetadata`, `PsbtExportOptions`, `PsbtFileExport`, `DescriptorPsbtBundle` types
- Property-based tests for descriptor import/export round-trip

### Changed
- Updated to v0.2.0

## [0.1.0] - 2026-01-02

### Added
- WIF export (compressed/uncompressed, mainnet/testnet)
- Hex export (with optional 0x prefix, uppercase)
- JSON export (single key and batch)
- CSV export (customizable columns)
- Paper wallet generation (P2PKH, P2WPKH, P2TR)
- BIP38 encryption export
- BIP21 URI generation for QR codes
