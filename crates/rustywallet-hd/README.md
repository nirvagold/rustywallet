# rustywallet-hd

BIP32/BIP44 Hierarchical Deterministic wallet for cryptocurrency key derivation.

## Features

- Create master keys from 64-byte seeds
- Derive child keys using BIP32 derivation
- Support BIP44 standard paths
- Export/import extended keys (xprv/xpub, tprv/tpub)
- Normal and hardened derivation
- Public key derivation from xpub (non-hardened only)
- Secure memory handling (zeroize on drop)

## Installation

```toml
[dependencies]
rustywallet-hd = "0.1"
```

## Usage

```rust
use rustywallet_hd::prelude::*;

// Create master key from seed (64 bytes, typically from mnemonic)
let seed = [0u8; 64];
let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet).unwrap();

// Derive BIP44 Bitcoin path: m/44'/0'/0'/0/0
let path = DerivationPath::bip44_bitcoin(0, 0, 0);
let child = master.derive_path(&path).unwrap();

// Get keys
let private_key = child.private_key().unwrap();
let public_key = child.public_key();

// Export as xprv/xpub
let xprv = child.to_xprv();
let xpub = child.extended_public_key().to_xpub();
```

## BIP44 Paths

```text
m / purpose' / coin_type' / account' / change / address_index

Bitcoin:  m/44'/0'/0'/0/0
Ethereum: m/44'/60'/0'/0/0
```

Helper methods:
```rust
// Bitcoin path
let btc_path = DerivationPath::bip44_bitcoin(account, change, index);

// Ethereum path
let eth_path = DerivationPath::bip44_ethereum(account, index);
```

## Integration with rustywallet-mnemonic

```rust
use rustywallet_mnemonic::prelude::*;
use rustywallet_hd::prelude::*;

// Generate mnemonic
let mnemonic = Mnemonic::generate(WordCount::Words12);

// Get seed
let seed = mnemonic.to_seed("passphrase");

// Create HD wallet
let master = ExtendedPrivateKey::from_seed(seed.as_bytes(), Network::Mainnet).unwrap();

// Derive keys
let path = DerivationPath::bip44_bitcoin(0, 0, 0);
let child = master.derive_path(&path).unwrap();
```

## Security

- Private keys and chain codes are zeroized on drop
- Debug output masks sensitive data
- Hardened derivation prevents public key derivation

## License

MIT
