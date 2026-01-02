# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-01-03

### Added

- Initial release
- X-only public keys (BIP340)
  - `XOnlyPublicKey` type with 32-byte representation
  - `Parity` enum for y-coordinate parity
  - Conversion from compressed public keys
  - Hex encoding/decoding
- Schnorr signatures (BIP340)
  - `SchnorrSignature` type (64 bytes)
  - `schnorr_sign` and `schnorr_sign_with_aux` functions
  - `schnorr_verify` function
- Tagged hashes
  - `tagged_hash` function for domain separation
  - `TapLeafHash`, `TapNodeHash`, `TapTweakHash` types
  - Predefined tags for BIP340/341
- Key tweaking
  - `tweak_public_key` for output key derivation
  - `tweak_private_key` for signing tweaked keys
  - `compute_tweak` for raw tweak computation
- TapTree construction
  - `TapTree` for script tree management
  - `TapLeaf` for individual scripts
  - `TapNode` for internal nodes
  - `TapTreeBuilder` for building trees
  - Helper functions: `single_leaf_tree`, `two_leaf_tree`
- Control blocks
  - `ControlBlock` for script path proofs
  - Serialization/deserialization
  - Verification against output keys
- Taproot outputs
  - `TaprootOutput` with key-path and script-path support
  - P2TR script pubkey generation
  - Bech32m address encoding
  - Address parsing and validation
- Signature hashes (BIP341)
  - `TaprootSighashType` enum
  - `taproot_key_path_sighash` function
  - `taproot_script_path_sighash` function
- Network support
  - Mainnet, Testnet, Signet, Regtest
