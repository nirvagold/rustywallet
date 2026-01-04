# Changelog

## [0.2.0] - 2026-01-04

### Added
- Descriptor import with `import_descriptor()` and `import_taproot_descriptor()`
- `DescriptorImport` struct with parsed descriptor metadata
- `ExtractedKey` struct for keys extracted from descriptors
- `KeyType` enum for different key types (pubkey, xpub, xprv, x-only, WIF, hex)
- `is_descriptor()` helper function
- Wallet format import support:
  - `import_electrum_wallet()` for Electrum JSON wallets
  - `import_sparrow_wallet()` for Sparrow JSON wallets
  - `import_bitcoin_core_wallet()` for Bitcoin Core wallet dumps
  - `import_wallet_auto()` for auto-detection
- `WalletFormat`, `WalletImport`, `WalletMetadata` types
- `ImportFormat::Descriptor` variant for format detection
- Dependency on `rustywallet-descriptor` v0.2

### Changed
- Updated to v0.2.0

## [0.1.0] - 2026-01-02

### Added
- WIF import with network and compression detection
- Hex import (64-char with optional 0x prefix)
- Mini key import (Casascius format)
- Mnemonic import with BIP44/49/84 derivation paths
- BIP38 encrypted key decryption
- Auto-detect format with `detect_format()`
- Unified `import_any()` function
