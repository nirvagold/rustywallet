#!/data/data/com.termux/files/usr/bin/bash
# RustyWallet Checker Demo - Termux Setup Script
# Run this script in Termux to build and run the checker

set -e

echo "========================================"
echo "  RustyWallet Checker - Termux Setup"
echo "========================================"
echo ""

# Check if running in Termux
if [ ! -d "/data/data/com.termux" ]; then
    echo "❌ This script must be run in Termux!"
    exit 1
fi

echo "[1/5] Updating packages..."
pkg update -y && pkg upgrade -y

echo "[2/5] Installing dependencies..."
pkg install -y rust git clang openssl pkg-config

echo "[3/5] Setting up environment..."
export OPENSSL_DIR=$PREFIX
export OPENSSL_INCLUDE_DIR=$PREFIX/include
export OPENSSL_LIB_DIR=$PREFIX/lib

echo "[4/5] Building rustywallet-checker-demo..."
# If running from repo root
if [ -f "Cargo.toml" ]; then
    cargo build --release -p rustywallet-checker-demo
    BINARY="./target/release/rustywallet-checker-demo"
# If running from examples/rustywallet-checker-demo
elif [ -f "../../Cargo.toml" ]; then
    cd ../..
    cargo build --release -p rustywallet-checker-demo
    BINARY="./target/release/rustywallet-checker-demo"
else
    echo "❌ Cannot find Cargo.toml. Please run from repo root or examples/rustywallet-checker-demo"
    exit 1
fi

echo "[5/5] Build complete!"
echo ""
echo "========================================"
echo "  ✅ Setup Complete!"
echo "========================================"
echo ""
echo "To run the checker:"
echo "  $BINARY"
echo ""
echo "Make sure you have addresses.txt in the current directory!"
echo ""
