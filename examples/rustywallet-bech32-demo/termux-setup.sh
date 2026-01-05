#!/data/data/com.termux/files/usr/bin/bash
# RustyWallet Bech32 Demo - Termux Setup Script

set -e

echo "========================================"
echo "  RustyWallet Bech32 - Termux Setup"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Step 1: Update packages
echo "Step 1/5: Updating packages..."
pkg update -y && pkg upgrade -y
print_status "Packages updated"

# Step 2: Install dependencies
echo ""
echo "Step 2/5: Installing dependencies..."
pkg install -y git rust openssl-tool pkg-config clang
print_status "Dependencies installed"

# Step 3: Setup storage
echo ""
echo "Step 3/5: Setting up storage access..."
termux-setup-storage || true
print_status "Storage setup complete"

# Step 4: Clone or update repo
echo ""
echo "Step 4/5: Setting up repository..."
cd ~
if [ -d "rustywallet" ]; then
    print_warning "Repository exists, pulling latest..."
    cd rustywallet
    git pull || true
else
    echo "Cloning repository..."
    git clone https://github.com/pfrfrfr/rustywallet.git
    cd rustywallet
fi
print_status "Repository ready"

# Step 5: Check addresses.txt
echo ""
echo "Step 5/5: Checking addresses.txt..."
if [ -f "addresses.txt" ]; then
    ADDR_COUNT=$(wc -l < addresses.txt)
    print_status "Found addresses.txt with $ADDR_COUNT addresses"
else
    print_warning "addresses.txt not found!"
    echo ""
    echo "Please copy addresses.txt to ~/rustywallet/"
    echo "Example:"
    echo "  cp ~/storage/shared/Download/addresses.txt ~/rustywallet/"
    echo ""
fi

# Build
echo ""
echo "========================================"
echo "  Building (this may take 5-10 minutes)"
echo "========================================"
echo ""

export OPENSSL_DIR=$PREFIX
cargo build --release -p rustywallet-bech32-demo

print_status "Build complete!"

echo ""
echo "========================================"
echo "  Setup Complete!"
echo "========================================"
echo ""
echo "To run the checker:"
echo "  cd ~/rustywallet"
echo "  ./target/release/rustywallet-bech32-demo"
echo ""
echo "Make sure addresses.txt is in ~/rustywallet/"
echo ""
