# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
