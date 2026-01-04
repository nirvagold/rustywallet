# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-01-03

### Added
- **Full Taproot Descriptor Support (BIP386)**
  - `TaprootDescriptor` enum with `KeyPath` and `ScriptPath` variants
  - Key-path only descriptors: `tr(KEY)`
  - Script-path descriptors with script trees: `tr(KEY,{SCRIPT})`
  - Nested script trees: `tr(KEY,{{SCRIPT,SCRIPT},{SCRIPT,SCRIPT}})`
  - Deeply nested trees with arbitrary depth
- **TapTree Implementation**
  - `TapDescriptorTree` for building script trees programmatically
  - `TapDescriptorLeaf` for individual script leaves
  - Support for `Leaf` and `Branch` node types
  - Conversion to `rustywallet-taproot` TapTree for address derivation
- **Tapscript Support**
  - `TapScript` enum for Taproot leaf scripts
  - `pk(KEY)` - Pay to pubkey in Tapscript
  - `pkh(KEY)` - Pay to pubkey hash in Tapscript
  - `multi_a(k,KEY,...)` - Tapscript multisig (OP_CHECKSIGADD)
  - `sortedmulti_a(k,KEY,...)` - Sorted Tapscript multisig
  - `raw(HEX)` - Raw script bytes
- **Address Derivation**
  - `TaprootDescriptor::derive_address()` for P2TR address generation
  - `TaprootDescriptor::derive_addresses()` for batch derivation
  - `TaprootDescriptor::derive_output()` for TaprootOutput generation
  - `TaprootDescriptor::script_pubkey()` for script pubkey generation
- **Round-Trip Support**
  - `Display` implementation for `TaprootDescriptor`
  - `Display` implementation for `TapDescriptorTree`
  - `Display` implementation for `TapScript`
  - Parse → Display → Parse produces equivalent descriptors
- **Re-exports**
  - `TaprootDescriptor`, `TapDescriptorTree`, `TapDescriptorLeaf`, `TapScript` from lib.rs
  - Added to prelude module for convenient imports

### Changed
- Updated crate description to highlight Taproot support
- Added `rustywallet-taproot` as dependency for Taproot output generation
- Enhanced documentation with Taproot examples

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
