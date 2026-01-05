//! rustywallet-psbt demo
//!
//! Demonstrates PSBT creation, parsing, signing, and finalization.

use rustywallet_psbt::{Psbt, PsbtError, TxOut, KeySource, PsbtSighashType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== rustywallet-psbt Demo ===\n");

    // Demo 1: Create PSBT from unsigned transaction
    demo_create_psbt()?;

    // Demo 2: Parse and inspect PSBT
    demo_parse_psbt()?;

    // Demo 3: PSBT v2
    demo_psbt_v2()?;

    // Demo 4: Update PSBT with UTXO info
    demo_update_psbt()?;

    // Demo 5: Combine PSBTs
    demo_combine_psbts()?;

    // Demo 6: Serialization
    demo_serialization()?;

    println!("\n=== All demos completed successfully! ===");
    Ok(())
}

fn demo_create_psbt() -> Result<(), PsbtError> {
    println!("--- Demo 1: Create PSBT ---");

    // Create a minimal unsigned transaction
    // Version (4) + input count (1) + input (41) + output count (1) + output (34) + locktime (4)
    let unsigned_tx = vec![
        // Version
        0x02, 0x00, 0x00, 0x00,
        // Input count
        0x01,
        // Input: txid (32 bytes)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        // Input: vout
        0x00, 0x00, 0x00, 0x00,
        // Input: scriptSig (empty)
        0x00,
        // Input: sequence
        0xff, 0xff, 0xff, 0xff,
        // Output count
        0x01,
        // Output: value (1 BTC = 100,000,000 satoshis)
        0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00,
        // Output: scriptPubKey (P2WPKH)
        0x16, // length
        0x00, 0x14, // OP_0 PUSH20
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14,
        // Locktime
        0x00, 0x00, 0x00, 0x00,
    ];

    let psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

    println!("  Created PSBT with:");
    println!("    Version: {}", psbt.version());
    println!("    Inputs: {}", psbt.input_count());
    println!("    Outputs: {}", psbt.output_count());

    Ok(())
}

fn demo_parse_psbt() -> Result<(), PsbtError> {
    println!("\n--- Demo 2: Parse PSBT ---");

    // Create a PSBT first
    let unsigned_tx = vec![
        0x02, 0x00, 0x00, 0x00, // version
        0x00, // no inputs
        0x00, // no outputs
        0x00, 0x00, 0x00, 0x00, // locktime
    ];

    let psbt = Psbt::from_unsigned_tx(unsigned_tx)?;
    let base64 = psbt.to_base64();

    println!("  Original PSBT (base64): {}...", &base64[..20.min(base64.len())]);

    // Parse it back
    let parsed = Psbt::from_base64(&base64)?;

    println!("  Parsed successfully!");
    println!("    Version: {}", parsed.version());
    println!("    Is v2: {}", parsed.is_v2());

    Ok(())
}

fn demo_psbt_v2() -> Result<(), PsbtError> {
    println!("\n--- Demo 3: PSBT v2 ---");

    // Create PSBT v2 (without embedded transaction)
    let psbt = Psbt::new_v2(2, 2);

    println!("  Created PSBT v2:");
    println!("    Version: {}", psbt.version());
    println!("    Is v2: {}", psbt.is_v2());
    println!("    Inputs: {}", psbt.input_count());
    println!("    Outputs: {}", psbt.output_count());

    Ok(())
}

fn demo_update_psbt() -> Result<(), PsbtError> {
    println!("\n--- Demo 4: Update PSBT ---");

    let unsigned_tx = vec![
        0x02, 0x00, 0x00, 0x00,
        0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00,
        0xff, 0xff, 0xff, 0xff,
        0x01,
        0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x16,
        0x00, 0x14,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14,
        0x00, 0x00, 0x00, 0x00,
    ];

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

    // Add witness UTXO
    let utxo = TxOut {
        value: 200_000_000, // 2 BTC
        script_pubkey: vec![
            0x00, 0x14, // P2WPKH
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14,
        ],
    };
    psbt.update_input_with_utxo(0, utxo)?;

    // Add BIP32 derivation
    let pubkey = vec![0x02; 33]; // Dummy compressed pubkey
    let key_source = KeySource::new(
        [0xde, 0xad, 0xbe, 0xef], // fingerprint
        vec![84 | 0x80000000, 0x80000000, 0x80000000, 0, 0], // m/84'/0'/0'/0/0
    );
    psbt.update_input_with_bip32(0, pubkey, key_source.clone())?;

    println!("  Updated PSBT with:");
    println!("    Witness UTXO: 2 BTC");
    println!("    BIP32 path: {}", key_source.path_string());

    // Check fee calculation
    if let Some(input_value) = psbt.total_input_value() {
        println!("    Total input value: {} satoshis", input_value);
    }

    Ok(())
}

fn demo_combine_psbts() -> Result<(), PsbtError> {
    println!("\n--- Demo 5: Combine PSBTs ---");

    let unsigned_tx = vec![
        0x02, 0x00, 0x00, 0x00,
        0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00,
        0xff, 0xff, 0xff, 0xff,
        0x01,
        0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x16,
        0x00, 0x14,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14,
        0x00, 0x00, 0x00, 0x00,
    ];

    // Create two PSBTs with different partial signatures
    let mut psbt1 = Psbt::from_unsigned_tx(unsigned_tx.clone())?;
    let mut psbt2 = Psbt::from_unsigned_tx(unsigned_tx)?;

    // Add different signatures to each
    psbt1.inputs[0].partial_sigs.insert(
        vec![0x02; 33], // pubkey 1
        vec![0x30, 0x44, 0x01, 0x02, 0x03], // signature 1
    );

    psbt2.inputs[0].partial_sigs.insert(
        vec![0x03; 33], // pubkey 2
        vec![0x30, 0x44, 0x04, 0x05, 0x06], // signature 2
    );

    println!("  PSBT 1 signatures: {}", psbt1.inputs[0].partial_sigs.len());
    println!("  PSBT 2 signatures: {}", psbt2.inputs[0].partial_sigs.len());

    // Combine
    let combined = Psbt::combine(&[psbt1, psbt2])?;

    println!("  Combined signatures: {}", combined.inputs[0].partial_sigs.len());

    Ok(())
}

fn demo_serialization() -> Result<(), PsbtError> {
    println!("\n--- Demo 6: Serialization ---");

    let unsigned_tx = vec![
        0x02, 0x00, 0x00, 0x00,
        0x00, // no inputs
        0x00, // no outputs
        0x00, 0x00, 0x00, 0x00,
    ];

    let psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

    // To bytes
    let bytes = psbt.to_bytes();
    println!("  Bytes length: {}", bytes.len());
    println!("  Bytes (hex): {}", hex::encode(&bytes[..bytes.len().min(40)]));

    // To base64
    let base64 = psbt.to_base64();
    println!("  Base64: {}", base64);

    // Display trait
    println!("  Display: {}", psbt);

    // FromStr trait
    let parsed: Psbt = base64.parse()?;
    println!("  Parsed from string: {} inputs", parsed.input_count());

    // Roundtrip verification
    assert_eq!(psbt.to_bytes(), parsed.to_bytes());
    println!("  Roundtrip: OK");

    Ok(())
}
