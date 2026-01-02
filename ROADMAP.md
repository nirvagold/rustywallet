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

### 18. rustywallet-psbt 🔜 Next
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

### 19. rustywallet-taproot 📋 Planned
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

### 20. rustywallet-descriptor 📋 Planned
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

### 21. rustywallet-recovery 📋 Planned
Wallet recovery tools

**Features:**
- Scan blockchain for funds
- Gap limit handling (configurable)
- Multi-path derivation scan (BIP44/49/84/86)
- UTXO aggregation
- Recovery report generation

**Dependencies:** rustywallet-hd, rustywallet-electrum

---

## 🔄 Phase 3.5: Crate Improvements (v2.x)

### rustywallet-tx v0.2
- [ ] RBF (Replace-By-Fee) - fee bumping
- [ ] CPFP (Child-Pays-For-Parent)
- [ ] Taproot signing (P2TR key path)
- [ ] Additional coin selection: Branch & Bound, Random
- [ ] Transaction batching utilities

### rustywallet-electrum v0.2
- [ ] SSL certificate pinning
- [ ] Server discovery (DNS seeds)
- [ ] Connection pooling
- [ ] Real-time subscriptions (address, headers)
- [ ] Batch request optimization

### rustywallet-mempool v0.2
- [ ] WebSocket support for real-time data
- [ ] Block subscription
- [ ] Lightning network stats
- [ ] Mining pool statistics

### rustywallet-multisig v0.2
- [ ] PSBT integration
- [ ] MuSig2 (Schnorr multisig)
- [ ] Coordinator protocol

### rustywallet-hd v0.2
- [ ] BIP85 - Deterministic entropy from BIP32
- [ ] SLIP39 (Shamir for mnemonic)
- [ ] Custom derivation path builder

### rustywallet-address v0.2
- [ ] Silent Payments (BIP352)
- [ ] Address validation improvements

### rustywallet-batch v0.2
- [ ] SIMD optimization
- [ ] Memory-mapped file output
- [ ] Resume capability

### rustywallet-vanity v0.2
- [ ] Regex pattern support
- [ ] Distributed search (network)

---

## ⚡ Phase 4: Lightning & Advanced (v3) 📋 PLANNED

### 22. rustywallet-lightning 📋 Planned
Lightning Network basics

**Features:**
- BOLT11 invoice parsing/creation
- Payment hash/preimage handling
- Channel point derivation
- Node ID from seed
- Route hints parsing

**Dependencies:** rustywallet-keys, rustywallet-hd

---

### 23. rustywallet-musig 📋 Planned
MuSig2 Schnorr multisig (BIP327)

**Features:**
- Key aggregation
- Nonce generation & aggregation
- Partial signature creation
- Signature aggregation
- Adaptor signatures

**Dependencies:** rustywallet-keys, rustywallet-taproot

---

### 24. rustywallet-frost 📋 Planned
FROST threshold signatures

**Features:**
- Distributed key generation (DKG)
- Threshold signing (t-of-n)
- Signature aggregation
- Robustness against malicious signers

**Dependencies:** rustywallet-keys

---

### 25. rustywallet-silent 📋 Planned
Silent Payments (BIP352)

**Features:**
- Silent payment address generation
- Scanning for payments
- Labeling support
- Change address handling

**Dependencies:** rustywallet-keys, rustywallet-address

---

### 26. rustywallet-coinjoin 📋 Planned
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
| Phase 3 (Advanced v2) | 4 crates | 📋 Planned |
| Phase 3.5 (Improvements) | 8 upgrades | 📋 Planned |
| Phase 4 (Lightning v3) | 5 crates | 📋 Planned |

**Total: 27 crates + 8 major upgrades**

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

### v2.x (Planned)
18. 🔜 rustywallet-psbt
19. 📋 rustywallet-taproot
20. 📋 rustywallet-descriptor
21. 📋 rustywallet-recovery
22. 📋 Crate improvements (v0.2 releases)

### v3.x (Planned)
23. 📋 rustywallet-lightning
24. 📋 rustywallet-musig
25. 📋 rustywallet-frost
26. 📋 rustywallet-silent
27. 📋 rustywallet-coinjoin

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
