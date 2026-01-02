# Changelog

All notable changes to this project will be documented in this file.

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
