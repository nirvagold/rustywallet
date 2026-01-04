# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-01-04

### Added
- **FROST Threshold Signatures** (t-of-n)
  - `FrostMultisig` struct for managing FROST threshold wallets
  - `FrostSigningRound` for coordinating signing rounds
  - `FrostParticipant` for individual signer operations
  - `FrostPsbtBuilder` for hardware wallet compatible PSBT workflows
  - P2TR address generation from FROST group public key
  - Integration with `rustywallet-frost` crate
  - Support for any t-of-n threshold configuration
  - Commitment and partial signature collection
  - Signature aggregation into valid Schnorr signatures

### Changed
- Updated version to 0.3.0
- Added `rustywallet-frost` dependency
- Updated keywords to include "frost"
- Enhanced documentation with FROST examples
- Updated prelude to export FROST types

## [0.2.0] - 2026-01-03

### Added
- **PSBT Integration**
  - `MultisigPsbtBuilder` for building multisig PSBTs
  - `PsbtPartialSig` for PSBT-compatible partial signatures
  - `sign_input()` method for signing with private keys
  - `build_witness()` and `build_script_sig()` for finalizing
  - Witness/non-witness UTXO support
- **MuSig2 Key Aggregation** (BIP327)
  - `MuSigKeyAgg` for n-of-n Schnorr multisig key aggregation
  - BIP327-compliant key sorting and coefficient computation
  - X-only public key output for Taproot
  - `musig_to_p2tr_address()` for P2TR address generation
  - Key tweaking support for Taproot

### Changed
- Updated keywords to include "musig" and "psbt"
- Enhanced documentation with PSBT and MuSig2 examples

## [0.1.0] - 2026-01-02

### Added
- Initial release
- `MultisigConfig` for M-of-N configuration (up to 15-of-15)
- `MultisigWallet` with P2SH, P2WSH, P2SH-P2WSH addresses
- BIP67 compliant key sorting
- Multisig redeem script generation
- P2SH and P2WSH partial signing
- Signature combination with threshold validation
- Shamir Secret Sharing (split/combine)
- GF(256) finite field arithmetic
- Share serialization (hex encoding)
