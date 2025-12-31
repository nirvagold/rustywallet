# Implementation Plan

- [ ] 1. Set up project structure and workspace
  - [x] 1.1 Initialize Cargo workspace with rustywallet-keys crate



    - Create `Cargo.toml` workspace root
    - Create `crates/rustywallet-keys/Cargo.toml` with dependencies (secp256k1, rand, zeroize, thiserror, bs58)
    - Create `crates/rustywallet-keys/src/lib.rs` with module declarations

    - _Requirements: 8.3, 8.4_
  - [x] 1.2 Set up module structure


    - Create `src/private_key.rs`, `src/public_key.rs`, `src/error.rs`, `src/network.rs`
    - Create `src/encoding/mod.rs`, `src/encoding/hex.rs`, `src/encoding/wif.rs`
    - Create `src/prelude.rs` with re-exports
    - _Requirements: 8.3_

- [x] 2. Implement error types






  - [x] 2.1 Create error module with all error types

    - Implement `PrivateKeyError` enum with variants: InvalidLength, InvalidHex, InvalidWif, OutOfRange, InvalidChecksum
    - Implement `PublicKeyError` enum with variants: InvalidLength, InvalidHex, InvalidPoint
    - Implement `KeyError` unified error type
    - Derive `thiserror::Error` for all types
    - _Requirements: 2.4, 4.4, 8.2_

- [x] 3. Implement Network enum






  - [x] 3.1 Create Network type

    - Implement `Network` enum with Mainnet and Testnet variants
    - Implement `wif_version_byte()` method
    - Derive Debug, Clone, Copy, PartialEq, Eq
    - _Requirements: 3.4_

- [x] 4. Implement internal encoding utilities




  - [x] 4.1 Implement hex encoding/decoding

    - Create `encode(bytes: &[u8]) -> String` function
    - Create `decode(hex: &str) -> Result<Vec<u8>, HexError>` function
    - Support case-insensitive decoding

    - _Requirements: 2.1, 2.5, 3.1_

  - [x] 4.2 Implement Base58Check encoding/decoding
    - Create `encode(data: &[u8]) -> String` using bs58 crate
    - Create `decode(encoded: &str) -> Result<Vec<u8>, Base58Error>` with checksum validation

    - _Requirements: 2.3, 3.3_
  - [x] 4.3 Implement WIF encoding/decoding


    - Create `encode(key: &[u8; 32], network: Network, compressed: bool) -> String`
    - Create `decode(wif: &str) -> Result<([u8; 32], Network, bool), WifError>`
    - Handle version byte and compression flag
    - _Requirements: 2.3, 3.3, 3.4_

- [x] 5. Implement PrivateKey struct



  - [x] 5.1 Create PrivateKey struct with core functionality
    - Define struct wrapping `secp256k1::SecretKey`
    - Implement `random()` using secure RNG
    - Implement `from_bytes([u8; 32]) -> Result<Self, PrivateKeyError>`
    - Implement `is_valid(bytes: &[u8; 32]) -> bool`

    - _Requirements: 1.1, 1.2, 1.3, 2.2, 4.1, 4.2, 4.3_
  - [x] 5.2 Write property test for random key validity

    - **Property 1: Random Key Validity**
    - **Validates: Requirements 1.1, 1.2**

  - [x] 5.3 Implement PrivateKey import methods
    - Implement `from_hex(hex: &str) -> Result<Self, PrivateKeyError>`
    - Implement `from_wif(wif: &str) -> Result<Self, PrivateKeyError>`

    - _Requirements: 2.1, 2.3, 2.5_
  - [x] 5.4 Implement PrivateKey export methods
    - Implement `to_bytes(&self) -> [u8; 32]`
    - Implement `to_hex(&self) -> String`
    - Implement `to_wif(&self, network: Network) -> String`
    - _Requirements: 3.1, 3.2, 3.3, 3.4_
  - [x] 5.5 Write property tests for PrivateKey round-trips


    - **Property 2: Hex Round-Trip**
    - **Property 3: Bytes Round-Trip**
    - **Property 4: WIF Round-Trip**
    - **Property 5: Hex Case Insensitivity**
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5**

  - [x] 5.6 Write property test for invalid input rejection

    - **Property 6: Invalid Input Rejection**
    - **Validates: Requirements 2.4, 4.1, 4.2, 4.3**

  - [x] 5.7 Implement security traits for PrivateKey
    - Implement `Drop` with zeroization using `zeroize` crate
    - Implement `Debug` with masked output `PrivateKey(****)`

    - _Requirements: 8.5_

  - [x] 5.8 Write property test for debug output security

    - **Property 11: Debug Output Security**
    - **Validates: Requirements 8.5**

- [x] 6. Checkpoint - Ensure all PrivateKey tests pass


  - Ensure all tests pass, ask the user if questions arise.




- [x] 7. Implement PublicKey struct
  - [x] 7.1 Create PublicKey struct with derivation
    - Define struct wrapping `secp256k1::PublicKey`
    - Define `PublicKeyFormat` enum (Compressed, Uncompressed)
    - Implement `from_private_key(private_key: &PrivateKey) -> Self`

    - Add `public_key(&self) -> PublicKey` method to PrivateKey
    - _Requirements: 5.1, 5.4_
  - [x] 7.2 Write property test for public key derivation determinism

    - **Property 7: Public Key Derivation Determinism**
    - **Validates: Requirements 5.4**

  - [x] 7.3 Implement PublicKey import methods
    - Implement `from_compressed(bytes: &[u8; 33]) -> Result<Self, PublicKeyError>`
    - Implement `from_uncompressed(bytes: &[u8; 65]) -> Result<Self, PublicKeyError>`
    - Implement `from_hex(hex: &str) -> Result<Self, PublicKeyError>`

    - _Requirements: 6.1, 6.2_
  - [x] 7.4 Implement PublicKey export methods
    - Implement `to_compressed(&self) -> [u8; 33]`
    - Implement `to_uncompressed(&self) -> [u8; 65]`
    - Implement `to_hex(&self, format: PublicKeyFormat) -> String`

    - Implement `to_bytes(&self, format: PublicKeyFormat) -> Vec<u8>`
    - _Requirements: 5.2, 5.3, 7.1, 7.2_

  - [x] 7.5 Write property tests for PublicKey format invariants
    - **Property 8: Public Key Format Invariants**

    - **Validates: Requirements 5.2, 5.3, 7.1, 7.2**
  - [x] 7.6 Write property test for PublicKey format round-trip
    - **Property 9: Public Key Format Round-Trip**
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.4**
  - [x] 7.7 Write property test for PublicKey serialization round-trip

    - **Property 10: Public Key Serialization Round-Trip**
    - **Validates: Requirements 7.3**

- [x] 8. Checkpoint - Ensure all PublicKey tests pass



  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. Finalize and polish



  - [x] 9.1 Complete prelude module

    - Re-export all public types in `src/prelude.rs`
    - Add documentation comments to prelude
    - _Requirements: 8.3_

  - [-] 9.2 Add crate-level documentation

    - Add `//!` doc comments to `lib.rs`
    - Add examples in documentation

    - _Requirements: 8.1_
  - [-] 9.3 Write unit tests for known test vectors


    - Test against BIP-340 test vectors for key derivation
    - Test WIF encoding against known Bitcoin addresses
    - _Requirements: 5.1_

- [x] 10. Final Checkpoint - Ensure all tests pass

  - Ensure all tests pass, ask the user if questions arise.



- [x] 11. Demo Project Validation

  - [x] 11.1 Create demo project

    - Create `examples/rustywallet-keys-demo/` project
    - Add dependency to rustywallet-keys crate
    - _Requirements: 8.1_

  - [-] 11.2 Write demo code

    - Demonstrate all public API: PrivateKey, PublicKey, Network
    - Show import/export in all formats (hex, WIF, bytes)



    - Handle error cases properly
    - _Requirements: 8.1, 8.3_


  - [x] 11.3 Run and verify demo











    - Execute demo project successfully
    - Verify all output is correct
    - Get user approval (ACC)
    - _Requirements: 8.1_
  - [ ] 11.4 Cleanup demo project
    - Delete `examples/rustywallet-keys-demo/` after ACC
    - _Requirements: N/A_

- [ ] 12. Pre-publish Checklist
  - [ ] 12.1 Run cargo clippy
    - Ensure no warnings
  - [ ] 12.2 Run cargo fmt
    - Ensure code is formatted
  - [ ] 12.3 Run cargo publish --dry-run
    - Verify publish will succeed
  - [ ] 12.4 Update ROADMAP.md
    - Change rustywallet-keys status to `✔️ Done`
    - Change rustywallet-address status to `✅ In Progress`
