# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-01-02

### Added
- Initial release
- `ElectrumClient` for Electrum protocol communication
- TCP and TLS/SSL connection support
- Balance checking (`get_balance`, `get_balances`)
- UTXO listing (`list_unspent`)
- Transaction operations (`get_transaction`, `broadcast`, `get_history`)
- Server methods (`server_version`, `ping`, `get_block_height`, `estimate_fee`)
- Address to scripthash conversion for all address types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- JSON-RPC batch requests for efficient multi-address queries
- Configurable timeout and retry settings
- Built-in list of public Electrum servers
