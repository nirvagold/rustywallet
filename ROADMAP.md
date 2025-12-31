# rustywallet - Roadmap

## Overview

**rustywallet** adalah ekosistem Rust crates untuk cryptocurrency wallet utilities dengan fokus pada Developer Experience (DX) yang clean dan type-safe.

## Crate Structure

```
rustywallet/
├── crates/
│   ├── rustywallet-keys/       # ✔️ Done
│   ├── rustywallet-address/    # ✔️ Done
│   ├── rustywallet-mnemonic/   # ✔️ Done
│   ├── rustywallet-hd/         # ✔️ Done
│   └── rustywallet-signer/     # ✔️ Done
├── rustywallet/                # ✔️ Done
└── rustywallet-cli/            # ✔️ Done
```

## Crates Detail

### 1. rustywallet-keys ✔️ (Done)
Private & Public Key management

**Features:**
- Generate random private key (CSPRNG)
- Import from hex, WIF, bytes
- Export to hex, WIF, bytes
- Validate private key
- Derive public key (compressed/uncompressed)
- Format conversion
- Secure memory handling (zeroize on drop)

**Spec:** `.kiro/specs/rustywallet-keys/`

---

### 2. rustywallet-address ✔️ (Done)
Address generation untuk berbagai blockchain

**Features:**
- Bitcoin Legacy (P2PKH) - prefix 1
- Bitcoin SegWit (P2WPKH) - prefix bc1q
- Bitcoin Taproot (P2TR) - prefix bc1p
- Ethereum (checksummed) - prefix 0x
- Address validation

**Dependencies:** rustywallet-keys

**Spec:** `.kiro/specs/rustywallet-address/`

---

### 3. rustywallet-mnemonic ✔️ (Done)
BIP39 Mnemonic / Seed Phrase

**Features:**
- Generate 12/24 word mnemonic
- Validate mnemonic
- Mnemonic → Seed → Private Key
- Multi-language wordlists (EN, ID, etc.)
- Passphrase support

**Spec:** `.kiro/specs/rustywallet-mnemonic/`

---

### 4. rustywallet-hd ✔️ (Done)
HD Wallet (BIP32/BIP44)

**Features:**
- Master key derivation from seed
- Child key derivation (hardened/normal)
- Standard derivation paths (m/44'/0'/0'/0/0)
- Extended keys (xpub, xprv)
- Account/address discovery

**Dependencies:** rustywallet-keys

**Spec:** `.kiro/specs/rustywallet-hd/`

---

### 5. rustywallet-signer ✔️ (Done)
Message & Transaction Signing

**Features:**
- Sign arbitrary messages
- Verify signatures
- ECDSA signatures (Bitcoin)
- Personal sign (Ethereum)
- Recoverable signatures

**Dependencies:** rustywallet-keys

**Spec:** `.kiro/specs/rustywallet-signer/`

---

### 6. rustywallet (Umbrella) ✔️ (Done)
Re-export semua crates dengan unified API

```rust
use rustywallet::prelude::*;

let key = PrivateKey::random();
let mnemonic = Mnemonic::generate(WordCount::Words12);
```

**Spec:** `.kiro/specs/rustywallet/`

---

### 7. rustywallet-cli ✔️ (Done)
Command-line tool

```bash
# Install
cargo install rustywallet-cli

# Usage
rustywallet generate
rustywallet address --key <hex> --type segwit
rustywallet mnemonic --words 12
rustywallet hd --mnemonic "..."
rustywallet sign --key <hex> --message "hello"
rustywallet verify --address <addr> --message "hello" --signature <sig>
```

---

## Publishing to crates.io

Setelah setiap crate selesai dan tested:

```bash
cd crates/rustywallet-keys
cargo publish
```

## Status Legend

- ✔️ Done - Selesai dan published ke crates.io
- ✅ In Progress - Sedang dikerjakan
- 🔜 Next - Akan dikerjakan setelah current selesai
- 📋 Planned - Sudah direncanakan, belum dimulai

## Pre-Publish Workflow

Sebelum publish setiap crate:
1. ✅ Semua tests passing (`cargo test`)
2. ✅ Clippy clean (`cargo clippy`)
3. ✅ Documentation lengkap
4. ✅ **Demo project berhasil** - buat project demo di `examples/` untuk validasi
5. ✅ `cargo publish --dry-run` sukses
6. ✅ Update ROADMAP.md → ubah status ke `✔️ Done`
