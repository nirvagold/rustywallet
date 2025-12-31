---
inclusion: always
---

# rustywallet Development Guidelines

## 🎯 Single Source of Truth

**ROADMAP.md adalah patokan utama project ini.**

Selalu baca `#[[file:ROADMAP.md]]` untuk mengetahui:
- Status setiap crate (✅ In Progress, 🔜 Next, 📋 Planned, ✔️ Done)
- Urutan pengembangan
- Fitur yang harus diimplementasi

## 📋 Progress Tracking

**WAJIB update ROADMAP.md setiap kali:**
1. Memulai crate baru → ubah status ke `✅ In Progress`
2. Menyelesaikan crate → ubah status ke `✔️ Done`
3. Menambah/mengubah fitur → update di section crate terkait

**Format status:**
- `✔️ Done` - Selesai dan published
- `✅ In Progress` - Sedang dikerjakan
- `🔜 Next` - Akan dikerjakan setelah current selesai
- `📋 Planned` - Sudah direncanakan, belum dimulai

## 📁 Spec Files

Setiap crate yang sedang dikerjakan harus punya spec di `.kiro/specs/<crate-name>/`:
- `requirements.md` - User stories dan acceptance criteria
- `design.md` - Architecture dan correctness properties
- `tasks.md` - Implementation checklist

**Current spec:** `.kiro/specs/rustywallet-keys/`

## Coding Standards

### Rust Style
- Gunakan `rustfmt` untuk formatting
- Gunakan `clippy` untuk linting
- Semua public items harus punya doc comments (`///`)
- Error handling dengan `Result<T, E>`, tidak boleh panic

### Security
- Private keys harus di-zeroize saat drop
- Debug output untuk private key harus di-mask
- Gunakan constant-time operations untuk crypto

### Testing
- Property-based testing dengan `proptest`
- Minimum 100 iterations per property test
- Setiap property test harus reference correctness property dari design doc
- Format: `// **Feature: rustywallet-keys, Property N: <name>**`

### Dependencies
- Prefer well-maintained crates (secp256k1, rand, bs58)
- Minimize dependencies
- Pin versions di Cargo.toml

## Workspace Structure

```
rustywallet/
├── Cargo.toml              # Workspace root
├── ROADMAP.md              # Project roadmap
├── crates/
│   └── rustywallet-keys/   # Current crate
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── private_key.rs
│           ├── public_key.rs
│           ├── error.rs
│           ├── network.rs
│           ├── prelude.rs
│           └── encoding/
│               ├── mod.rs
│               ├── hex.rs
│               └── wif.rs
└── .kiro/
    ├── steering/
    └── specs/
```

## Publishing Checklist

Sebelum publish ke crates.io:
- [ ] Semua tests passing
- [ ] Documentation lengkap
- [ ] CHANGELOG.md updated
- [ ] Version bump di Cargo.toml
- [ ] **Demo project berhasil** (lihat section Demo Project)
- [ ] `cargo publish --dry-run` sukses
- [ ] **Update ROADMAP.md** → ubah status crate ke `✔️ Done`

## 🧪 Demo Project Workflow

**WAJIB buat demo project sebelum publish untuk memastikan crate berfungsi dengan benar.**

### Langkah-langkah:

1. **Buat demo project** di `examples/<crate-name>-demo/`
   ```bash
   cargo new examples/rustywallet-keys-demo
   ```

2. **Tambahkan dependency** ke crate yang akan di-test
   ```toml
   # examples/rustywallet-keys-demo/Cargo.toml
   [dependencies]
   rustywallet-keys = { path = "../../crates/rustywallet-keys" }
   ```

3. **Tulis demo code** yang menggunakan semua fitur utama:
   - Generate key
   - Import/export berbagai format
   - Derive public key
   - Error handling

4. **Run demo** dan pastikan berjalan tanpa error
   ```bash
   cargo run -p rustywallet-keys-demo
   ```

5. **Setelah user ACC**, hapus demo project
   ```bash
   rm -rf examples/rustywallet-keys-demo
   ```

### Demo Project Structure:
```
rustywallet/
├── crates/
│   └── rustywallet-keys/
├── examples/                    # Demo projects (temporary)
│   └── rustywallet-keys-demo/   # Hapus setelah ACC
│       ├── Cargo.toml
│       └── src/main.rs
└── ...
```

### Demo Code Requirements:
- Gunakan semua public API dari crate
- Tampilkan output yang jelas
- Handle semua error cases
- Tidak boleh panic

## Workflow: Selesai Satu Crate

Ketika menyelesaikan satu crate:
1. Pastikan semua tasks di `tasks.md` sudah ✅
2. Run `cargo test` - semua harus pass
3. Run `cargo clippy` - tidak ada warnings
4. Update ROADMAP.md:
   - Ubah status crate selesai ke `✔️ Done`
   - Ubah status crate berikutnya ke `✅ In Progress`
5. Buat spec baru untuk crate berikutnya di `.kiro/specs/<next-crate>/`
