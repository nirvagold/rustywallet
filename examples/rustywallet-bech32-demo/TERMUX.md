# RustyWallet Bech32 Demo - Termux Setup

## 📱 Instalasi di Termux (Android)

### 1. Install Termux
Download dari F-Droid (JANGAN dari Play Store - versi lama):
- https://f-droid.org/packages/com.termux/

### 2. Setup Termux
```bash
# Update packages
pkg update && pkg upgrade -y

# Install dependencies
pkg install -y git rust openssl-tool pkg-config clang

# Setup storage access
termux-setup-storage
```

### 3. Clone Repository
```bash
cd ~
git clone https://github.com/pfrfrfr/rustywallet.git
cd rustywallet
```

### 4. Copy addresses.txt
Copy file `addresses.txt` ke folder rustywallet:
```bash
# Dari internal storage
cp ~/storage/shared/Download/addresses.txt .

# Atau dari folder lain
cp /path/to/addresses.txt .
```

### 5. Build & Run
```bash
# Build release (butuh waktu ~5-10 menit pertama kali)
cargo build --release -p rustywallet-bech32-demo

# Run
./target/release/rustywallet-bech32-demo
```

## ⚡ Quick Setup (One-liner)
```bash
pkg update -y && pkg install -y git rust openssl-tool pkg-config clang && termux-setup-storage
```

## 🔧 Troubleshooting

### Error: "linker cc not found"
```bash
pkg install -y clang
```

### Error: "openssl not found"
```bash
pkg install -y openssl-tool pkg-config
export OPENSSL_DIR=$PREFIX
```

### Build sangat lambat
Normal untuk pertama kali. Build berikutnya akan lebih cepat karena cache.

### Out of memory saat build
```bash
# Tambah swap (butuh root)
# Atau build dengan less parallelism:
cargo build --release -p rustywallet-bech32-demo -j 2
```

### Permission denied
```bash
chmod +x ./target/release/rustywallet-bech32-demo
```

## 📊 Expected Performance

| Device | Cores | Speed |
|--------|-------|-------|
| Snapdragon 8 Gen 2 | 8 | ~80-120K/s |
| Snapdragon 888 | 8 | ~60-90K/s |
| Snapdragon 765G | 8 | ~40-60K/s |
| MediaTek Dimensity | 8 | ~50-80K/s |
| Budget phones | 4-8 | ~20-40K/s |

## 📁 Output Files

- `found_bech32.txt` - Semua bloom matches dengan info lengkap
- `found_bech32_balance.txt` - Hanya yang punya balance

## 🛑 Stop Program
Tekan `Ctrl+C` untuk stop dengan aman.

## 💡 Tips

1. **Jalankan saat charging** - proses ini CPU intensive
2. **Gunakan Termux:Float** - bisa minimize tanpa kill process
3. **Disable battery optimization** untuk Termux di settings Android
4. **Gunakan Termux:Boot** untuk auto-start saat reboot
