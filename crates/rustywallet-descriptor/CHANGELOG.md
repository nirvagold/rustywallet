# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-01-03

### Added
- Initial release
- Descriptor parsing for pk, pkh, wpkh, sh, wsh, tr, multi, sortedmulti
- BIP380 checksum computation and verification
- Key expression parsing (raw pubkey, xpub/xprv, derivation paths, key origins)
- Wildcard support for HD wallet descriptors
- Script generation for all descriptor types
- Address derivation with network support (mainnet/testnet)
- Range derivation for wildcard descriptors
