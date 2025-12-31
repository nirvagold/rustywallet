# Requirements Document

## Introduction

**rustywallet-keys** adalah Rust crate yang menyediakan fondasi untuk manajemen private key dan public key dalam konteks cryptocurrency. Crate ini dirancang dengan fokus pada Developer Experience (DX) yang clean, type-safe, dan mudah digunakan. Library ini akan menjadi fondasi untuk crate-crate lain dalam ekosistem rustywallet.

## Glossary

- **Private Key**: Bilangan acak 256-bit yang digunakan untuk menandatangani transaksi dan membuktikan kepemilikan aset crypto
- **Public Key**: Titik pada kurva elliptic (secp256k1) yang diturunkan dari private key, digunakan untuk verifikasi signature
- **Compressed Public Key**: Representasi 33-byte dari public key (prefix 02/03 + x-coordinate)
- **Uncompressed Public Key**: Representasi 65-byte dari public key (prefix 04 + x + y coordinates)
- **WIF (Wallet Import Format)**: Format Base58Check untuk encoding private key Bitcoin
- **Hex**: Representasi hexadecimal dari bytes
- **secp256k1**: Kurva elliptic yang digunakan Bitcoin dan Ethereum

## Requirements

### Requirement 1: Private Key Generation

**User Story:** As a developer, I want to generate cryptographically secure random private keys, so that I can create new wallets programmatically.

#### Acceptance Criteria

1. WHEN a developer calls the random key generation function THEN the System SHALL produce a valid 256-bit private key using a cryptographically secure random number generator
2. WHEN generating a private key THEN the System SHALL ensure the key is within the valid secp256k1 range (1 to n-1, where n is the curve order)
3. WHEN a generated key is invalid (zero or >= curve order) THEN the System SHALL automatically regenerate until a valid key is produced

### Requirement 2: Private Key Import

**User Story:** As a developer, I want to import private keys from various formats, so that I can work with existing keys in my application.

#### Acceptance Criteria

1. WHEN a developer provides a 64-character hex string THEN the System SHALL parse and create a valid PrivateKey instance
2. WHEN a developer provides a 32-byte array THEN the System SHALL create a valid PrivateKey instance
3. WHEN a developer provides a WIF-encoded string THEN the System SHALL decode and create a valid PrivateKey instance
4. WHEN a developer provides invalid input (wrong length, invalid characters, invalid checksum) THEN the System SHALL return a descriptive error indicating the specific validation failure
5. WHEN parsing a hex string THEN the System SHALL accept both lowercase and uppercase characters

### Requirement 3: Private Key Export

**User Story:** As a developer, I want to export private keys to various formats, so that I can store or transfer keys between systems.

#### Acceptance Criteria

1. WHEN a developer requests hex export THEN the System SHALL return a 64-character lowercase hex string
2. WHEN a developer requests bytes export THEN the System SHALL return a 32-byte array
3. WHEN a developer requests WIF export THEN the System SHALL return a valid Base58Check encoded string with appropriate version byte
4. WHEN exporting to WIF THEN the System SHALL support both mainnet (0x80) and testnet (0xEF) version bytes
5. WHEN a PrivateKey is serialized and then deserialized THEN the System SHALL produce an equivalent PrivateKey

### Requirement 4: Private Key Validation

**User Story:** As a developer, I want to validate private keys before using them, so that I can prevent errors from invalid keys.

#### Acceptance Criteria

1. WHEN validating a private key THEN the System SHALL verify the key is not zero
2. WHEN validating a private key THEN the System SHALL verify the key is less than the secp256k1 curve order
3. WHEN a developer provides a potentially invalid key THEN the System SHALL provide a validation function that returns a boolean result
4. WHEN validation fails THEN the System SHALL provide specific error information about why the key is invalid

### Requirement 5: Public Key Derivation

**User Story:** As a developer, I want to derive public keys from private keys, so that I can generate addresses and verify signatures.

#### Acceptance Criteria

1. WHEN a developer calls the public key derivation function THEN the System SHALL compute the correct secp256k1 public key point
2. WHEN deriving a public key THEN the System SHALL support output in compressed format (33 bytes)
3. WHEN deriving a public key THEN the System SHALL support output in uncompressed format (65 bytes)
4. WHEN the same private key is used multiple times THEN the System SHALL produce identical public keys

### Requirement 6: Public Key Format Conversion

**User Story:** As a developer, I want to convert public keys between formats, so that I can work with different blockchain requirements.

#### Acceptance Criteria

1. WHEN a developer has a compressed public key THEN the System SHALL provide conversion to uncompressed format
2. WHEN a developer has an uncompressed public key THEN the System SHALL provide conversion to compressed format
3. WHEN converting between formats THEN the System SHALL preserve the underlying key data
4. WHEN a PublicKey is converted to compressed and back to uncompressed THEN the System SHALL produce an equivalent PublicKey

### Requirement 7: Public Key Export

**User Story:** As a developer, I want to export public keys to various formats, so that I can use them in different contexts.

#### Acceptance Criteria

1. WHEN a developer requests hex export THEN the System SHALL return the appropriate hex string (66 chars compressed, 130 chars uncompressed)
2. WHEN a developer requests bytes export THEN the System SHALL return the appropriate byte array (33 or 65 bytes)
3. WHEN a PublicKey is serialized and then deserialized THEN the System SHALL produce an equivalent PublicKey

### Requirement 8: Developer Experience

**User Story:** As a developer, I want a clean and intuitive API, so that I can integrate the library quickly without extensive documentation reading.

#### Acceptance Criteria

1. WHEN using the library THEN the System SHALL provide method chaining for common operations
2. WHEN errors occur THEN the System SHALL return descriptive error types that implement std::error::Error
3. WHEN using the library THEN the System SHALL provide a prelude module for convenient imports
4. WHEN building with default features THEN the System SHALL have minimal dependencies
5. WHEN displaying keys for debugging THEN the System SHALL implement Debug trait with masked output for security
