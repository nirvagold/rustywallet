# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-01-02

### Added
- Initial release
- `MempoolClient` for Mempool.space API communication
- Fee estimation (`get_fees`)
- Address methods (`get_address`, `get_utxos`, `get_address_txs`)
- Transaction methods (`get_tx`, `get_tx_hex`, `broadcast`)
- Block methods (`get_block_height`, `get_block_hash`, `get_block`)
- Support for mainnet, testnet, and signet
- Custom endpoint support
