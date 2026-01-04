# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-01-04

### Added
- **Taproot (P2TR) Vanity Support** - Full support for Taproot vanity addresses
  - Generate vanity addresses starting with `bc1p` (mainnet) or `tb1p` (testnet)
  - Taproot difficulty estimation with `DifficultyEstimate.calculate()`
  - Property test for Taproot vanity match validity (Property 16)
  - Unit tests for Taproot address generation and testnet support
- Documentation updates for Taproot usage examples

### Changed
- Updated to version 0.3.0
- Enhanced README with Taproot examples and distributed search documentation

## [0.2.0] - 2026-01-03

### Added
- **Regex Pattern Support** - Full regex matching for flexible patterns
  - `RegexPattern` for custom regex patterns
  - `CommonPatterns` helper with pre-built patterns
  - `starts_with()`, `ends_with()`, `contains()` helpers
  - `repeated_char()`, `numeric_sequence()`, `letter_sequence()`
  - Case-insensitive regex matching
  - Difficulty estimation for regex patterns
- **Distributed Search** - Multi-worker search coordination
  - `SearchCoordinator` for work distribution
  - `SearchWorker` for processing work units
  - `WorkUnit` and `WorkResult` for serializable work items
  - `DistributedConfig` for configuration
  - `run_distributed_search()` for local multi-threaded search
  - Progress callbacks during distributed search

### Changed
- Updated to version 0.2.0
- Added `regex`, `serde`, `serde_json` dependencies

## [0.1.3] - 2026-01-02

### Added
- Initial release
- `VanityGenerator` - fluent API for vanity address generation
- `Pattern` - prefix, suffix, and contains pattern matching
- `AddressType` - support for P2PKH, P2WPKH, P2TR, Ethereum
- `DifficultyEstimate` - time and probability estimation
- `VanityConfig` - comprehensive configuration options
- Case-sensitive and case-insensitive matching
- Multi-pattern search (first match wins)
- Parallel search with rayon
- Progress callbacks for long-running searches
- Timeout and max attempts limits
