# Security Best Practices

This guide covers security considerations when building Bitcoin wallets with rustywallet.

## Key Security

### Memory Protection

rustywallet automatically zeroizes sensitive data when dropped:

```rust
use rustywallet_keys::PrivateKey;

{
    let key = PrivateKey::random();
    // Use the key...
} // Key is automatically zeroized here

// The memory that held the key is now zeroed
```

### Avoid Logging Private Keys

```rust
use rustywallet_keys::PrivateKey;

let key = PrivateKey::random();

// GOOD: Debug output is masked
println!("{:?}", key);  // Output: PrivateKey([REDACTED])

// BAD: Never do this
// println!("Key: {}", key.to_hex());  // Exposes key!
// log::debug!("Generated key: {:?}", key.to_bytes());  // Exposes key!
```

### Secure Key Generation

```rust
use rustywallet_keys::PrivateKey;

// GOOD: Use cryptographically secure RNG
let key = PrivateKey::random();  // Uses OS entropy

// BAD: Never use predictable sources
// let key = PrivateKey::from_bytes(&[1u8; 32]);  // Predictable!
// let key = PrivateKey::from_seed(timestamp);    // Predictable!
```

## Mnemonic Security

### Generate Securely

```rust
use rustywallet_mnemonic::Mnemonic;

// GOOD: Generate with proper entropy
let mnemonic = Mnemonic::generate(24)?;  // 256 bits of entropy

// Verify entropy source
assert!(mnemonic.entropy().len() >= 32);
```

### Handle Carefully

```rust
// GOOD: Minimize exposure time
let mnemonic = Mnemonic::generate(24)?;
let seed = mnemonic.to_seed("");
let master = ExtendedPrivateKey::from_seed(&seed)?;
drop(mnemonic);  // Zeroize immediately after use

// BAD: Long-lived mnemonic in memory
// static MNEMONIC: Mnemonic = ...;  // Don't do this!
```

### Passphrase Recommendations

```rust
// GOOD: Use a strong passphrase
let seed = mnemonic.to_seed("correct-horse-battery-staple");

// The passphrase:
// - Adds another layer of security
// - Creates a completely different wallet
// - Should be memorable but not guessable
// - Is NOT recoverable if forgotten!
```

## Network Security

### Electrum Connections

```rust
use rustywallet_electrum::{ElectrumClient, ElectrumConfig};

// GOOD: Use SSL/TLS
let config = ElectrumConfig {
    url: "ssl://electrum.blockstream.info:50002",
    verify_ssl: true,
    ..Default::default()
};

// GOOD: Use Tor for privacy
let config = ElectrumConfig {
    url: "ssl://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion:50002",
    proxy: Some("socks5://127.0.0.1:9050"),
    ..Default::default()
};

// BAD: Unencrypted connection
// let config = ElectrumConfig {
//     url: "tcp://electrum.example.com:50001",  // No encryption!
// };
```

### API Rate Limiting

```rust
use std::time::Duration;
use std::thread::sleep;

// GOOD: Respect rate limits
for address in addresses {
    let balance = client.get_balance(&address)?;
    sleep(Duration::from_millis(100));  // Rate limit
}

// BAD: Hammering the API
// for address in addresses {
//     let balance = client.get_balance(&address)?;  // May get blocked
// }
```

## Transaction Security

### Verify Before Signing

```rust
use rustywallet_tx::{TransactionBuilder, Transaction};

let tx = TransactionBuilder::new()
    .add_input(utxo)
    .add_output(recipient, amount)
    .add_change(change_address, change_amount)
    .build()?;

// GOOD: Verify transaction details
assert_eq!(tx.outputs[0].address, recipient);
assert_eq!(tx.outputs[0].value, amount);
assert!(tx.fee() <= max_acceptable_fee);

// Then sign
let signed = tx.sign(&private_key)?;
```

### Fee Validation

```rust
// GOOD: Validate fee is reasonable
let fee = tx.fee();
let fee_rate = fee as f64 / tx.virtual_size() as f64;

if fee_rate > 1000.0 {  // > 1000 sat/vB is suspicious
    return Err("Fee rate too high - possible error");
}

if fee_rate < 1.0 {  // < 1 sat/vB may not confirm
    return Err("Fee rate too low - may not confirm");
}
```

### Change Address Verification

```rust
// GOOD: Verify change goes to your address
let change_output = &tx.outputs[1];
assert!(my_addresses.contains(&change_output.address));

// BAD: Trust builder blindly
// let tx = builder.build()?;
// let signed = tx.sign(&key)?;  // What if change goes elsewhere?
```

## Multisig Security

### Key Distribution

```rust
use rustywallet_multisig::{MultisigConfig, MultisigWallet};

// GOOD: Keys from independent sources
let config = MultisigConfig::new(2, 3)?;  // 2-of-3

// Key 1: Hardware wallet
// Key 2: Mobile wallet
// Key 3: Paper backup

// BAD: All keys from same source
// let key1 = master.derive("m/0")?;
// let key2 = master.derive("m/1")?;
// let key3 = master.derive("m/2")?;  // Single point of failure!
```

### Verify Cosigner Keys

```rust
// GOOD: Verify each cosigner's key independently
let pubkey1 = get_pubkey_from_hardware_wallet()?;
let pubkey2 = get_pubkey_from_mobile_wallet()?;
let pubkey3 = get_pubkey_from_paper_backup()?;

// Verify addresses match expected
let wallet = MultisigWallet::new(config, vec![pubkey1, pubkey2, pubkey3])?;
assert_eq!(wallet.address(), expected_address);
```

## Storage Security

### Encrypted Export

```rust
use rustywallet_export::export_bip38;

// GOOD: Encrypt before storing
let encrypted = export_bip38(&key, "strong-password", Network::Mainnet)?;
std::fs::write("key.bip38", encrypted)?;

// BAD: Plain text storage
// std::fs::write("key.txt", key.to_wif())?;  // Anyone can read!
```

### Secure Deletion

```rust
use std::fs::{File, remove_file};
use std::io::Write;

// GOOD: Overwrite before deleting
fn secure_delete(path: &str) -> std::io::Result<()> {
    let metadata = std::fs::metadata(path)?;
    let size = metadata.len() as usize;
    
    // Overwrite with zeros
    let mut file = File::create(path)?;
    file.write_all(&vec![0u8; size])?;
    file.sync_all()?;
    
    // Then delete
    remove_file(path)?;
    Ok(())
}

// BAD: Simple delete (data may be recoverable)
// std::fs::remove_file("key.txt")?;
```

## Input Validation

### Address Validation

```rust
use rustywallet_address::Address;

// GOOD: Validate addresses before use
fn validate_recipient(address: &str) -> Result<Address, Error> {
    let addr = Address::from_string(address)?;
    
    // Check network
    if addr.network() != Network::Mainnet {
        return Err("Wrong network");
    }
    
    // Check address type is acceptable
    match addr.address_type() {
        AddressType::P2PKH | AddressType::P2WPKH | AddressType::P2TR => Ok(addr),
        _ => Err("Unsupported address type"),
    }
}

// BAD: Trust user input
// let recipient = user_input;  // Could be invalid or wrong network!
```

### Amount Validation

```rust
// GOOD: Validate amounts
fn validate_amount(satoshis: u64) -> Result<u64, Error> {
    // Check not zero
    if satoshis == 0 {
        return Err("Amount cannot be zero");
    }
    
    // Check not dust
    if satoshis < 546 {
        return Err("Amount below dust limit");
    }
    
    // Check reasonable maximum
    if satoshis > 21_000_000 * 100_000_000 {
        return Err("Amount exceeds total supply");
    }
    
    Ok(satoshis)
}
```

## Constant-Time Operations

rustywallet uses constant-time operations for cryptographic comparisons:

```rust
// Internally, comparisons use constant-time equality
// to prevent timing attacks

// GOOD: Use provided comparison methods
if key1 == key2 {  // Constant-time comparison
    // ...
}

// BAD: Manual byte comparison (timing leak)
// if key1.to_bytes() == key2.to_bytes() {  // Variable time!
// }
```

## Checklist

### Before Deployment

- [ ] All private keys are zeroized after use
- [ ] No private keys in logs or error messages
- [ ] SSL/TLS for all network connections
- [ ] Input validation on all user data
- [ ] Fee validation before signing
- [ ] Change address verification
- [ ] Encrypted storage for sensitive data

### Key Management

- [ ] Keys generated from secure entropy
- [ ] Mnemonic passphrases used where appropriate
- [ ] Backup strategy tested
- [ ] Recovery process documented and tested

### Multisig Setup

- [ ] Keys from independent sources
- [ ] Cosigner keys verified independently
- [ ] Threshold appropriate for use case
- [ ] Recovery plan for lost keys

### Network Security

- [ ] Using encrypted connections (SSL/TLS)
- [ ] Rate limiting implemented
- [ ] Tor/proxy for privacy-sensitive operations
- [ ] Server certificate verification enabled

## Common Vulnerabilities

| Vulnerability | Prevention |
|--------------|------------|
| Key leakage in logs | Use masked Debug impl |
| Weak entropy | Use OS-provided RNG |
| Timing attacks | Constant-time operations |
| Man-in-the-middle | SSL/TLS verification |
| Dust attacks | Minimum output validation |
| Fee sniping | Verify fee before signing |
| Address reuse | Generate new addresses |

## Next Steps

- [Key Management](../guides/key-management.md)
- [Shamir Secret Sharing](./shamir.md)
- [Multi-Signature Wallets](../guides/multisig.md)
