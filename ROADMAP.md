# rustywallet - Roadmap

## Overview

**rustywallet** adalah ekosistem Rust crates untuk cryptocurrency wallet utilities dengan fokus pada Developer Experience (DX) yang clean dan type-safe.

---

## 📦 Phase 1: Core Crates (v1) ✔️ COMPLETE

```
rustywallet/
├── crates/
│   ├── rustywallet-keys/       # ✔️ Done
│   ├── rustywallet-address/    # ✔️ Done
│   ├── rustywallet-mnemonic/   # ✔️ Done
│   ├── rustywallet-hd/         # ✔️ Done
│   ├── rustywallet-signer/     # ✔️ Done
│   ├── rustywallet-checker/    # ✔️ Done
│   ├── rustywallet-bloom/      # ✔️ Done (internal)
│   └── rustywallet-cli/        # ✔️ Done
└── rustywallet/                # ✔️ Done (umbrella)
```

---

## 🚀 Phase 2: Performance Crates (v2)

### 9. rustywallet-batch ✔️ Done
High-performance batch key generation

**Features:**
- Batch key generation dengan parallel processing
- Incremental key scanning (EC point addition)
- FastKeyGenerator dengan ChaCha20 RNG (7M+ keys/sec)
- Memory-efficient streaming
- Target: 1M+ keys/sec ✅ Achieved

**Dependencies:** rustywallet-keys, rayon

---

### 10. rustywallet-vanity ✔️ Done
Vanity address generator

**Features:**
- Generate custom prefix addresses (1Love..., 1BTC...)
- Multi-pattern matching
- Difficulty estimation
- Progress callback
- Case-insensitive matching
- Support P2PKH, P2WPKH, P2TR, Ethereum

**Dependencies:** rustywallet-keys, rustywallet-address, rustywallet-batch

---

### 11. rustywallet-gpu ⏸️ Paused
GPU-accelerated key generation (requires dedicated GPU)

**Features:**
- OpenCL backend
- CUDA backend (optional)
- Hybrid CPU+GPU mode
- Target: 10M+ keys/sec

**Dependencies:** rustywallet-batch, opencl3

**Note:** Paused - requires dedicated GPU (NVIDIA/AMD) for meaningful performance gains.

---

## 🔧 Phase 3: Utility Crates

### 12. rustywallet-import ✔️ Done
Import dari berbagai wallet formats

**Features:**
- WIF import (compressed/uncompressed)
- Hex import (64-char)
- Mini key import (Casascius)
- Mnemonic import with BIP44/49/84 paths
- BIP38 encrypted key decryption
- Auto-detect format

**Dependencies:** rustywallet-keys, rustywallet-mnemonic, rustywallet-hd, rustywallet-address

---

### 13. rustywallet-export ✔️ Done
Export ke berbagai formats

**Features:**
- QR code generation
- Paper wallet PDF
- Electrum format export
- JSON/CSV export
- Encrypted backup

**Dependencies:** rustywallet-keys, qrcode, printpdf

---

## 🌐 Phase 4: Network Crates

### 14. rustywallet-electrum ✔️ Done
Electrum protocol client

**Features:**
- Electrum server connection (TCP/SSL)
- Batch balance checking (no rate limit!)
- UTXO fetching
- Transaction broadcasting
- Server discovery

**Dependencies:** tokio, rustls

---

### 15. rustywallet-mempool ✔️ Done
Mempool.space API integration

**Features:**
- Fee estimation (low/medium/high)
- Transaction tracking
- Block explorer data
- Address history
- Webhook support

**Dependencies:** reqwest, rustywallet-checker

---

## 💰 Phase 5: Transaction Crates

### 16. rustywallet-tx 📋 Planned
Transaction building

**Features:**
- Build Bitcoin transactions
- PSBT (Partially Signed Bitcoin Transaction)
- Coin selection algorithms
- Fee calculation
- RBF (Replace-By-Fee)
- SegWit/Taproot support

**Dependencies:** rustywallet-keys, rustywallet-signer

---

### 17. rustywallet-multisig 📋 Planned
Multi-signature wallets

**Features:**
- M-of-N multisig setup
- Shamir Secret Sharing (SSS)
- Threshold signatures
- Coordinator-less signing
- Hardware wallet integration

**Dependencies:** rustywallet-keys, rustywallet-tx

---

## 📊 Progress Summary

| Phase | Crates | Status |
|-------|--------|--------|
| Phase 1 (Core) | 9 crates | ✔️ Complete |
| Phase 2 (Performance) | 3 crates | ✅ In Progress |
| Phase 3 (Utility) | 2 crates | 📋 Planned |
| Phase 4 (Network) | 2 crates | 📋 Planned |
| Phase 5 (Transaction) | 2 crates | 📋 Planned |

**Total: 18 crates**

---

## Status Legend

- ✔️ Done - Selesai dan published ke crates.io
- ✅ In Progress - Sedang dikerjakan
- 🔜 Next - Akan dikerjakan setelah current selesai
- 📋 Planned - Sudah direncanakan, belum dimulai

---

## Development Order (Phase 2+)

1. **rustywallet-batch** ✔️ Done
2. **rustywallet-vanity** ✔️ Done
3. **rustywallet-gpu** ⏸️ Paused (needs dedicated GPU)
4. **rustywallet-electrum** ✔️ Done
5. **rustywallet-mempool** ✔️ Done
6. **rustywallet-import** ✔️ Done
7. **rustywallet-export** ✔️ Done
8. **rustywallet-tx** ← CURRENT
9. rustywallet-multisig

---

## Pre-Publish Workflow

Sebelum publish setiap crate:
1. ✅ Semua tests passing (`cargo test`)
2. ✅ Clippy clean (`cargo clippy`)
3. ✅ Documentation lengkap
4. ✅ **Demo project berhasil**
5. ✅ `cargo publish --dry-run` sukses
6. ✅ Update ROADMAP.md → ubah status ke `✔️ Done`
7. ✅ Git commit & push
