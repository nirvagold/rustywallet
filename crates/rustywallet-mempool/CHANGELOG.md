# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-01-03

### Added
- **WebSocket Support** (`websocket` module)
  - `MempoolWsClient` for real-time updates
  - `WsSubscription` for configuring subscriptions
  - `WsSubscriptionBuilder` for fluent subscription building
  - Event types: `BlockEvent`, `MempoolInfoEvent`, `AddressTxEvent`, `TxConfirmedEvent`
  - `WsConnectionStatus` for connection state tracking
  - WebSocket URLs for mainnet, testnet, signet
- **Lightning Network Stats** (`lightning` module)
  - `get_lightning_stats()` - Network capacity, nodes, channels
  - `get_lightning_node()` - Node information by pubkey
  - `get_node_channels()` - Channels for a node
  - `get_lightning_channel()` - Channel information
  - `get_top_nodes_by_capacity()` - Top nodes ranking
  - Types: `LightningStats`, `LightningNode`, `LightningChannel`
- **Mining Pool Stats** (`mining` module)
  - `get_hashrate_distribution()` - Pool hashrate shares
  - `get_difficulty_adjustment()` - Next difficulty change
  - `get_mining_pool()` - Pool information
  - `get_pool_blocks()` - Blocks mined by pool
  - `get_block_rewards()` - Block reward statistics
  - Types: `MiningPoolStats`, `HashrateDistribution`, `DifficultyAdjustment`, `PoolBlock`
- New error types: `WebSocketError`, `WebSocketClosed`, `LightningError`, `MiningError`
- `base_url()` and `http_client()` accessor methods on `MempoolClient`

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
