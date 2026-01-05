# Running RustyWallet Checker on Termux (Android)

## Prerequisites

1. Install [Termux](https://f-droid.org/en/packages/com.termux/) from F-Droid (NOT Play Store!)
2. Android device with ARM64 processor (most modern phones)

## Quick Setup

### Option 1: Using Setup Script

```bash
# Clone the repo
pkg install git
git clone https://github.com/YOUR_USERNAME/rustywallet.git
cd rustywallet

# Run setup script
chmod +x examples/rustywallet-checker-demo/termux-setup.sh
./examples/rustywallet-checker-demo/termux-setup.sh
```

### Option 2: Manual Setup

```bash
# Update packages
pkg update && pkg upgrade

# Install dependencies
pkg install rust git clang openssl pkg-config

# Clone repo
git clone https://github.com/YOUR_USERNAME/rustywallet.git
cd rustywallet

# Set OpenSSL paths
export OPENSSL_DIR=$PREFIX
export OPENSSL_INCLUDE_DIR=$PREFIX/include
export OPENSSL_LIB_DIR=$PREFIX/lib

# Build
cargo build --release -p rustywallet-checker-demo

# Copy your addresses.txt to current directory
# Then run:
./target/release/rustywallet-checker-demo
```

## Transferring Files

### Transfer addresses.txt to Termux:

```bash
# From your PC, use adb:
adb push addresses.txt /sdcard/Download/

# In Termux:
cp /sdcard/Download/addresses.txt .
```

Or use Termux's built-in file access:
```bash
termux-setup-storage
cp ~/storage/downloads/addresses.txt .
```

## Performance Notes

- ARM64 phones typically get 20K-50K keys/second
- High-end phones (Snapdragon 8 Gen 2+) can reach 80K+ keys/second
- Battery usage will be high during scanning
- Consider running while charging

## Troubleshooting

### OpenSSL errors
```bash
pkg install openssl-tool
export OPENSSL_DIR=$PREFIX
```

### Out of memory
Reduce `BATCH_SIZE` in the source code to 50_000 or lower.

### Build fails
```bash
# Clean and rebuild
cargo clean
cargo build --release -p rustywallet-checker-demo
```

## Running in Background

To keep running when Termux is closed:

```bash
# Install termux-services
pkg install termux-services

# Or use nohup
nohup ./target/release/rustywallet-checker-demo > output.log 2>&1 &
```

## Storage Location

Found matches are saved to:
- `found.txt` - All bloom filter matches
- `found_with_balance.txt` - Matches with actual balance
