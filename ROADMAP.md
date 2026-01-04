# rustywallet - Roadmap

## Overview

**rustywallet** adalah ekosistem Rust crates untuk cryptocurrency wallet utilities dengan fokus pada Developer Experience (DX) yang clean dan type-safe.

---

## 📦 Phase 1: Core Crates (v1) ✔️ COMPLETE

| Crate | Status | Description |
|-------|--------|-------------|
| rustywallet-keys | ✔️ Done | Private & Public key management |
| rustywallet-address | ✔️ Done | Address generation (P2PKH, P2SH, P2WPKH, P2TR, ETH) |
| rustywallet-mnemonic | ✔️ Done | BIP39 mnemonic/seed phrase |
| rustywallet-hd | ✔️ Done | HD Wallet (BIP32/BIP44/BIP84) |
| rustywallet-signer | ✔️ Done | Message & transaction signing |
| rustywallet-checker | ✔️ Done | Address balance checking via APIs |
| rustywallet-bloom | ✔️ Done | Bloom filter for address matching |
| rustywallet-cli | ✔️ Done | Command-line interface |
| rustywallet | ✔️ Done | Umbrella crate |

---

## 🚀 Phase 2: Performance & Network (v1.x) ✔️ COMPLETE

| Crate | Status | Description |
|-------|--------|-------------|
| rustywallet-batch | ✔️ Done | High-performance batch key generation (7M+ keys/sec) |
| rustywallet-vanity | ✔️ Done | Vanity address generator |
| rustywallet-electrum | ✔️ Done | Electrum protocol client |
| rustywallet-mempool | ✔️ Done | Mempool.space API integration |
| rustywallet-import | ✔️ Done | Import from wallet formats |
| rustywallet-export | ✔️ Done | Export to various formats |
| rustywallet-tx | ✔️ Done | Transaction building & signing |
| rustywallet-multisig | ✔️ Done | Multi-signature wallets + Shamir |
| rustywallet-gpu | ⏸️ Paused | GPU-accelerated generation |

---

## 🔧 Phase 3: Advanced Features (v2) 📋 PLANNED

### 18. rustywallet-psbt ✔️ Done
PSBT (BIP174) for hardware wallet interoperability

**Features:**
- Parse/create PSBT
- Add inputs/outputs to PSBT
- Sign PSBT with private keys
- Finalize & extract transaction
- Combine PSBTs from multiple signers
- PSBT v2 (BIP370) support

**Dependencies:** rustywallet-tx, rustywallet-keys

---

### 19. rustywallet-taproot ✔️ Done
Full Taproot support (BIP340/341/342)

**Features:**
- Schnorr signatures (BIP340)
- Taproot key path spending
- Tapscript (script path spending)
- MAST (Merkelized Alternative Script Trees)
- Tweak key derivation
- Control block generation

**Dependencies:** rustywallet-keys, rustywallet-tx

---

### 20. rustywallet-descriptor ✔️ Done
Output descriptors (BIP380-386)

**Features:**
- Parse descriptor strings
- Support: `pk()`, `pkh()`, `wpkh()`, `sh()`, `wsh()`, `tr()`
- Derive addresses from descriptors
- Checksum validation
- Range derivation for HD descriptors
- Basic Miniscript support

**Dependencies:** rustywallet-keys, rustywallet-address, rustywallet-hd

---

### 21. rustywallet-recovery ✔️ Done
Wallet recovery tools

**Features:**
- Scan blockchain for funds
- Gap limit handling (configurable)
- Multi-path derivation scan (BIP44/49/84/86)
- UTXO aggregation
- Recovery report generation

**Dependencies:** rustywallet-hd, rustywallet-electrum

---

## 🔄 Phase 3.5: Crate Improvements (v2.x) ✔️ COMPLETE

### Ecosystem Upgrade v2 Progress

| Batch | Status | Crates |
|-------|--------|--------|
| Batch 1: Foundation | ✔️ Complete | rustywallet-signer v0.2, rustywallet-batch v0.3 |
| Batch 2: TX Integration | ✔️ Complete | rustywallet-tx v0.3, rustywallet-psbt v0.2 |
| Batch 3: Privacy & Recovery | ✔️ Complete | rustywallet-electrum v0.3, rustywallet-recovery v0.2 |
| Batch 4: Descriptor | ✔️ Complete | rustywallet-descriptor v0.2, rustywallet-hd v0.3 |
| Batch 5: Feature Completion | ✔️ Complete | rustywallet-multisig v0.3, rustywallet-coinjoin v0.2 |
| Batch 6: Polish | ✔️ Complete | mnemonic v0.2, import/export v0.2, vanity v0.3, checker v0.2, bloom v0.2, lightning v0.2, address v0.3 |

#### Batch 1 Completed Features:
- **rustywallet-signer v0.2**: Schnorr signing integration (BIP340)
  - SchnorrSigner trait with sign_schnorr() method
  - SchnorrVerifier trait with verify_schnorr() method
  - Re-exports from rustywallet-taproot
  - Property test: Schnorr sign-verify round-trip ✔️

- **rustywallet-batch v0.3**: Address generation
  - BatchAddressType enum (P2PKH, P2WPKH, P2TR)
  - BatchAddressGenerator struct
  - Parallel address generation with streaming output
  - Property test: Batch address consistency ✔️

#### Batch 2 Completed Features:
- **rustywallet-tx v0.3**: Advanced signing integration
  - sign_musig2() for MuSig2 transaction signing
  - sign_frost() for FROST threshold signing
  - create_silent_payment_outputs() for Silent Payment support
  - Property tests: MuSig2, FROST, Silent Payment ✔️

- **rustywallet-psbt v0.2**: Advanced signatures
  - add_musig2_partial_sig() for MuSig2 partial signatures
  - add_frost_partial_sig() for FROST partial signatures
  - combine_musig2_psbt() for PSBT aggregation
  - finalize_threshold_psbt() for threshold finalization
  - Property tests: Partial signature storage, aggregation ✔️

#### Batch 3 Completed Features:
- **rustywallet-electrum v0.3**: Silent Payment scanning
  - SilentPaymentScanner struct with Electrum backend
  - scan_blocks() for Silent Payment detection
  - DetectedPayment struct with spending key
  - Label support for multiple addresses
  - Property test: Silent Payment detection ✔️

- **rustywallet-recovery v0.2**: Parallel scanning
  - ParallelRecoveryScanner struct
  - scan_parallel() with connection pooling
  - Descriptor support including tr()
  - Progress reporting callback
  - Result aggregation
  - Property test: Recovery result aggregation ✔️

#### Batch 4 Completed Features:
- **rustywallet-descriptor v0.2**: Taproot descriptor support
  - TaprootDescriptor enum (KeyPath, ScriptPath)
  - TapTree for nested script trees
  - derive_address() for Taproot descriptors
  - Support for tr(KEY) and tr(KEY,{SCRIPT}) formats
  - Property test: Taproot descriptor round-trip ✔️

- **rustywallet-hd v0.3**: Path builder & SLIP39
  - DerivationPathBuilder struct with fluent API
  - BIP44/49/84/86 presets
  - Path validation for component ranges
  - Slip39 struct for Shamir secret sharing
  - Multi-group support for SLIP39
  - Property tests: Derivation path round-trip, SLIP39 split/combine ✔️

#### Batch 5 Completed Features:
- **rustywallet-multisig v0.3**: FROST threshold integration
  - FrostMultisig struct from FROST DKG
  - start_signing() for FROST signing rounds
  - add_partial_sig() and finalize() for signature aggregation
  - PSBT integration for hardware wallet compatibility
  - Property test: FROST multisig aggregation ✔️

- **rustywallet-coinjoin v0.2**: PSBT-based CoinJoin workflow
  - PsbtCoinJoinBuilder struct for PSBT-based CoinJoin
  - combine_participant_psbts() for merging signatures
  - finalize() with validation for all inputs signed
  - PsbtPayJoin for BIP78 workflow
  - Property test: CoinJoin PSBT merge ✔️

#### Batch 6 Completed Features:
- **rustywallet-mnemonic v0.2**: Multi-language support
  - Language enum with 5 languages (English, Japanese, Spanish, Chinese, Korean)
  - generate_with_language() for specific wordlist
  - parse_auto_detect() for automatic language detection
  - Property test: Multi-language mnemonic round-trip ✔️

- **rustywallet-import v0.2**: Descriptor import
  - Descriptor string parsing and key extraction
  - Wallet format support (Electrum, Sparrow, Bitcoin Core)
  - Property test: Descriptor import/export round-trip ✔️

- **rustywallet-export v0.2**: Descriptor export
  - Descriptor string generation with checksum
  - PSBT export alongside descriptors
  - Wallet format export support

- **rustywallet-vanity v0.3**: Taproot support
  - P2TR vanity address generation
  - bc1p prefix pattern matching
  - Taproot difficulty estimation
  - Property test: Taproot vanity match validity ✔️

- **rustywallet-checker v0.2**: Electrum backend
  - ElectrumChecker with Electrum protocol
  - Batch balance checking via Electrum
  - Fallback to API providers
  - Connection caching

- **rustywallet-bloom v0.2**: Counting filter
  - CountingBloomFilter with 4-bit counters
  - insert() with counter increment
  - remove() with underflow protection
  - Property test: Counting bloom filter insert/remove ✔️

- **rustywallet-address v0.3**: Descriptor derivation
  - Address::from_descriptor() method
  - Support for all descriptor types (pkh, wpkh, sh, wsh, tr)
  - Wildcard derivation for ranged descriptors
  - Property test: Descriptor address derivation consistency ✔️

- **rustywallet-lightning v0.2**: BOLT12 offers
  - Bolt12Offer struct for reusable payment requests
  - parse() and encode() for BOLT12 offers
  - Signature validation
  - Property test: BOLT12 offer round-trip ✔️

---

### rustywallet-tx v0.2 ✔️ Done
- [x] RBF (Replace-By-Fee) - fee bumping
- [x] Taproot signing (P2TR key path)
- [ ] CPFP (Child-Pays-For-Parent)
- [ ] Additional coin selection: Branch & Bound, Random
- [ ] Transaction batching utilities

### rustywallet-electrum v0.2 ✔️ Done
- [x] SSL certificate pinning
- [x] Server discovery (DNS seeds)
- [x] Connection pooling
- [x] Real-time subscriptions (address, headers)
- [x] Batch request optimization

### rustywallet-mempool v0.2 ✔️ Done
- [x] WebSocket support for real-time data
- [x] Block subscription
- [x] Lightning network stats
- [x] Mining pool statistics

### rustywallet-multisig v0.2 ✔️ Done
- [x] PSBT integration
- [x] MuSig2 (Schnorr multisig) key aggregation
- [ ] Coordinator protocol

### rustywallet-hd v0.2 ✔️ Done
- [x] BIP85 - Deterministic entropy from BIP32
- [x] SLIP39 (Shamir for mnemonic)
- [x] Custom derivation path builder

### rustywallet-address v0.2 ✔️ Done
- [x] Silent Payments (BIP352)
- [x] Address validation improvements

### rustywallet-batch v0.2 ✔️ Done
- [x] SIMD optimization
- [x] Memory-mapped file output
- [x] Resume capability

### rustywallet-vanity v0.2 ✔️ Done
- [x] Regex pattern support
- [x] Distributed search (network)

---

## ⚡ Phase 4: Lightning & Advanced (v3) 📋 PLANNED

### 22. rustywallet-lightning ✔️ Done
Lightning Network basics

**Features:**
- BOLT11 invoice parsing/creation
- Payment hash/preimage handling
- Channel point derivation
- Node ID from seed
- Route hints parsing

**Dependencies:** rustywallet-keys

---

### 23. rustywallet-musig ✔️ Done
MuSig2 Schnorr multisig (BIP327)

**Features:**
- Key aggregation
- Nonce generation & aggregation
- Partial signature creation
- Signature aggregation
- Adaptor signatures

**Dependencies:** rustywallet-keys, rustywallet-taproot

---

### 24. rustywallet-frost ✔️ Done
FROST threshold signatures

**Features:**
- Distributed key generation (DKG)
- Threshold signing (t-of-n)
- Signature aggregation
- Robustness against malicious signers

**Dependencies:** rustywallet-keys

---

### 25. rustywallet-silent ✔️ Done
Silent Payments (BIP352)

**Features:**
- Silent payment address generation
- Scanning for payments
- Labeling support
- Change address handling

**Dependencies:** rustywallet-keys, rustywallet-address

---

### 26. rustywallet-coinjoin ✔️ Done
CoinJoin utilities

**Features:**
- PayJoin (BIP78) support
- CoinJoin transaction building
- Equal output amounts
- Coordinator-less protocol

**Dependencies:** rustywallet-tx, rustywallet-psbt

---

## 📊 Progress Summary

| Phase | Crates | Status |
|-------|--------|--------|
| Phase 1 (Core) | 9 crates | ✔️ Complete |
| Phase 2 (Performance & Network) | 9 crates | ✔️ Complete |
| Phase 3 (Advanced v2) | 4 crates | ✔️ Complete |
| Phase 3.5 (Improvements) | 18 upgrades | ✔️ Complete |
| Phase 4 (Lightning v3) | 5 crates | ✔️ Complete |

**Total: 27 crates + 18 major upgrades**

---

## Status Legend

- ✔️ Done - Published ke crates.io
- ✅ In Progress - Sedang dikerjakan
- 🔜 Next - Akan dikerjakan selanjutnya
- 📋 Planned - Sudah direncanakan
- ⏸️ Paused - Ditunda

---

## Development Order

### v1.x (Complete)
1. ✔️ rustywallet-keys
2. ✔️ rustywallet-address
3. ✔️ rustywallet-mnemonic
4. ✔️ rustywallet-hd
5. ✔️ rustywallet-signer
6. ✔️ rustywallet-checker
7. ✔️ rustywallet-bloom
8. ✔️ rustywallet-cli
9. ✔️ rustywallet (umbrella)
10. ✔️ rustywallet-batch
11. ✔️ rustywallet-vanity
12. ✔️ rustywallet-electrum
13. ✔️ rustywallet-mempool
14. ✔️ rustywallet-import
15. ✔️ rustywallet-export
16. ✔️ rustywallet-tx
17. ✔️ rustywallet-multisig

### v2.x (Complete)
18. ✔️ rustywallet-psbt
19. ✔️ rustywallet-taproot
20. ✔️ rustywallet-descriptor
21. ✔️ rustywallet-recovery
22. ✔️ Crate improvements (v0.2/v0.3 releases)

### v3.x (Complete)
23. ✔️ rustywallet-lightning
24. ✔️ rustywallet-musig
25. ✔️ rustywallet-frost
26. ✔️ rustywallet-silent
27. ✔️ rustywallet-coinjoin

---

## Pre-Publish Workflow

Sebelum publish setiap crate:
1. ✅ Semua tests passing (`cargo test`)
2. ✅ Clippy clean (`cargo clippy`)
3. ✅ Documentation lengkap
4. ✅ Demo project berhasil
5. ✅ `cargo publish --dry-run` sukses
6. ✅ Update ROADMAP.md
7. ✅ Git commit & push
