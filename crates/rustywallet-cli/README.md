# rustywallet-cli

Command-line tool for cryptocurrency wallet operations.

## Installation

```bash
cargo install rustywallet-cli
```

## Usage

### Generate Private Key

```bash
# Generate hex format
rustywallet generate

# Generate WIF format
rustywallet generate --format wif --network mainnet
```

### Generate Mnemonic

```bash
# Generate 12-word mnemonic
rustywallet mnemonic

# Generate 24-word mnemonic with seed
rustywallet mnemonic --words 24 --show-seed

# Validate existing mnemonic
rustywallet mnemonic --validate "word1 word2 ... word12"
```

### Derive Address

```bash
# SegWit address (default)
rustywallet address --key <hex>

# Legacy P2PKH address
rustywallet address --key <hex> --type legacy

# Taproot address
rustywallet address --key <hex> --type taproot

# Ethereum address
rustywallet address --key <hex> --type ethereum
```

### HD Wallet Derivation

```bash
# Default BIP44 path (m/44'/0'/0'/0/0)
rustywallet hd --mnemonic "word1 word2 ... word12"

# Custom derivation path
rustywallet hd --mnemonic "..." --path "m/44'/60'/0'/0/0" --address-type ethereum

# With passphrase
rustywallet hd --mnemonic "..." --passphrase "secret"
```

### Sign Message

```bash
# Bitcoin message signing (BIP-137)
rustywallet sign --key <hex> --message "Hello" --format bitcoin

# Ethereum personal_sign (EIP-191)
rustywallet sign --key <hex> --message "Hello" --format ethereum
```

### Verify Signature

```bash
# Verify Bitcoin signature
rustywallet verify --address 1... --message "Hello" --signature <base64> --format bitcoin

# Verify Ethereum signature
rustywallet verify --address 0x... --message "Hello" --signature <hex> --format ethereum
```

## License

MIT
