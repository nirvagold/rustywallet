# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-01-03

### Added
- **RBF (Replace-By-Fee) support** (BIP125)
  - `is_rbf_enabled()` - Check if transaction is replaceable
  - `enable_rbf()` / `disable_rbf()` - Toggle RBF on inputs
  - `create_replacement()` - Create fee-bumped replacement transaction
  - `bump_fee()` - Increase fee on existing transaction
  - `RbfBuilder` - Helper for creating RBF-enabled inputs
  - `rbf_sequence` module with sequence constants
- **Taproot (P2TR) signing support**
  - `sign_p2tr_key_path()` - Sign P2TR key-path input
  - `sign_p2tr_key_path_with_sighash()` - Sign with explicit sighash type
  - `sign_all_p2tr()` - Sign multiple P2TR inputs
  - `is_p2tr_script()` - Check if script is P2TR
  - `extract_p2tr_pubkey()` - Extract x-only pubkey from P2TR script
- New error types: `RbfNotEnabled`, `RbfFeeTooLow`, `InvalidOutputIndex`, `TaprootError`

### Changed
- Updated keywords to include "taproot"
- Added `rustywallet-taproot` dependency

## [0.1.0] - 2026-01-02

### Added
- Initial release
- `Transaction`, `TxInput`, `TxOutput`, `Utxo` types
- Transaction serialization (legacy and SegWit)
- `TxBuilder` for creating unsigned transactions
- Coin selection with largest-first algorithm
- Fee calculation (vsize-based)
- Dust threshold detection
- Script building (P2PKH, P2WPKH, P2TR)
- Sighash calculation (legacy and BIP143)
- P2PKH signing
- P2WPKH signing (SegWit)
- Address to script conversion (P2PKH, P2WPKH)
