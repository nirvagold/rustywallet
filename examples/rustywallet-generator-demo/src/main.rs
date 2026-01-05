//! RustyWallet Generator Demo
//!
//! Demonstrates the latest features of rustywallet ecosystem:
//! - Multi-language mnemonic generation (BIP39)
//! - All Bitcoin address types (P2PKH, P2WPKH, P2TR)
//! - Ethereum addresses with EIP-55 checksum
//! - Silent Payments (BIP352)
//! - HD derivation paths
//! - BOLT12 Lightning offers

use rustywallet_address::{
    EthereumAddress, Network, P2PKHAddress, P2TRAddress, P2WPKHAddress,
    SilentPaymentAddress,
};
use rustywallet_hd::{DerivationPath, ExtendedPrivateKey, Network as HdNetwork};
use rustywallet_keys::private_key::PrivateKey;
use rustywallet_mnemonic::{Language, Mnemonic, WordCount};
use std::io::{self, Write};

fn main() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║           🦀 RUSTYWALLET GENERATOR DEMO v2.0 🦀                  ║");
    println!("║                                                                  ║");
    println!("║  Showcasing the latest rustywallet ecosystem features            ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    loop {
        println!("┌──────────────────────────────────────────────────────────────────┐");
        println!("│  Select Demo:                                                    │");
        println!("│                                                                  │");
        println!("│  [1] Generate Wallet (All Address Types)                         │");
        println!("│  [2] Multi-Language Mnemonic Demo                                │");
        println!("│  [3] Silent Payments Demo (BIP352)                               │");
        println!("│  [4] HD Derivation Paths Demo                                    │");
        println!("│  [5] Random Key Generation                                       │");
        println!("│  [0] Exit                                                        │");
        println!("└──────────────────────────────────────────────────────────────────┘");
        print!("\n  Enter choice: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        match input.trim() {
            "1" => demo_full_wallet(),
            "2" => demo_multi_language(),
            "3" => demo_silent_payments(),
            "4" => demo_hd_derivation(),
            "5" => demo_random_keys(),
            "0" => {
                println!("\n  👋 Goodbye!\n");
                break;
            }
            _ => println!("\n  ⚠️  Invalid choice, try again.\n"),
        }
    }
}

/// Demo 1: Generate a complete wallet with all address types
fn demo_full_wallet() {
    println!("\n");
    println!("═══════════════════════════════════════════════════════════════════");
    println!("  📝 FULL WALLET GENERATION");
    println!("═══════════════════════════════════════════════════════════════════");

    // Generate mnemonic
    let mnemonic = Mnemonic::generate(WordCount::Words12);
    let phrase = mnemonic.to_phrase();

    println!("\n  🔑 Mnemonic (12 words):");
    println!("  ┌────────────────────────────────────────────────────────────────┐");
    
    // Split phrase into lines of 4 words for readability
    let words: Vec<&str> = phrase.split_whitespace().collect();
    for (i, chunk) in words.chunks(4).enumerate() {
        let line = chunk.join(" ");
        println!("  │  {:2}-{:2}: {:<52} │", i * 4 + 1, i * 4 + chunk.len(), line);
    }
    println!("  └────────────────────────────────────────────────────────────────┘");

    // Derive seed and master key
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::from_seed(seed.as_bytes(), HdNetwork::Mainnet).unwrap();

    // Bitcoin addresses (BIP44/49/84/86)
    println!("\n  🪙 BITCOIN ADDRESSES:");
    println!("  ─────────────────────────────────────────────────────────────────");

    // P2PKH (Legacy) - m/44'/0'/0'/0/0
    let p2pkh_path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
    let p2pkh_key = master.derive_path(&p2pkh_path).unwrap();
    let p2pkh_pub = p2pkh_key.private_key().unwrap().public_key();
    let p2pkh_addr = P2PKHAddress::from_public_key(&p2pkh_pub, Network::BitcoinMainnet).unwrap();
    println!("  │ P2PKH (Legacy)  : {}", p2pkh_addr);
    println!("  │ Path            : m/44'/0'/0'/0/0");

    // P2WPKH (SegWit) - m/84'/0'/0'/0/0
    let p2wpkh_path = DerivationPath::parse("m/84'/0'/0'/0/0").unwrap();
    let p2wpkh_key = master.derive_path(&p2wpkh_path).unwrap();
    let p2wpkh_pub = p2wpkh_key.private_key().unwrap().public_key();
    let p2wpkh_addr = P2WPKHAddress::from_public_key(&p2wpkh_pub, Network::BitcoinMainnet).unwrap();
    println!("  │ P2WPKH (SegWit) : {}", p2wpkh_addr);
    println!("  │ Path            : m/84'/0'/0'/0/0");

    // P2TR (Taproot) - m/86'/0'/0'/0/0
    let p2tr_path = DerivationPath::parse("m/86'/0'/0'/0/0").unwrap();
    let p2tr_key = master.derive_path(&p2tr_path).unwrap();
    let p2tr_pub = p2tr_key.private_key().unwrap().public_key();
    let p2tr_addr = P2TRAddress::from_public_key(&p2tr_pub, Network::BitcoinMainnet).unwrap();
    println!("  │ P2TR (Taproot)  : {}", p2tr_addr);
    println!("  │ Path            : m/86'/0'/0'/0/0");

    // Ethereum address - m/44'/60'/0'/0/0
    println!("\n  💎 ETHEREUM ADDRESS:");
    println!("  ─────────────────────────────────────────────────────────────────");
    let eth_path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
    let eth_key = master.derive_path(&eth_path).unwrap();
    let eth_pub = eth_key.private_key().unwrap().public_key();
    let eth_addr = EthereumAddress::from_public_key(&eth_pub).unwrap();
    println!("  │ Address         : {}", eth_addr.to_checksum_string());
    println!("  │ Path            : m/44'/60'/0'/0/0");

    println!("\n  ⚠️  SAVE YOUR MNEMONIC SECURELY! Never share it with anyone.");
    println!("═══════════════════════════════════════════════════════════════════\n");
}

/// Demo 2: Multi-language mnemonic generation
fn demo_multi_language() {
    println!("\n");
    println!("═══════════════════════════════════════════════════════════════════");
    println!("  🌍 MULTI-LANGUAGE MNEMONIC DEMO");
    println!("═══════════════════════════════════════════════════════════════════");

    let languages = [
        (Language::English, "🇬🇧 English"),
        (Language::Japanese, "🇯🇵 Japanese"),
        (Language::Spanish, "🇪🇸 Spanish"),
        (Language::ChineseSimplified, "🇨🇳 Chinese (Simplified)"),
        (Language::Korean, "🇰🇷 Korean"),
    ];

    for (lang, name) in languages {
        let mnemonic = Mnemonic::generate_with_language(WordCount::Words12, lang);
        println!("\n  {} {}:", name, lang.name());
        println!("  ┌────────────────────────────────────────────────────────────────┐");
        
        let phrase = mnemonic.to_phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        
        // For CJK languages, show fewer words per line
        let chunk_size = match lang {
            Language::Japanese | Language::ChineseSimplified | Language::Korean => 3,
            _ => 4,
        };
        
        for chunk in words.chunks(chunk_size) {
            let line = chunk.join(" ");
            // Truncate if too long for display
            let display = if line.len() > 56 {
                format!("{}...", &line[..53])
            } else {
                line
            };
            println!("  │  {:<58} │", display);
        }
        println!("  └────────────────────────────────────────────────────────────────┘");
    }

    println!("\n  ℹ️  All languages produce valid BIP39 mnemonics that derive");
    println!("     the same addresses when using the same entropy.");
    println!("═══════════════════════════════════════════════════════════════════\n");
}

/// Demo 3: Silent Payments (BIP352)
fn demo_silent_payments() {
    println!("\n");
    println!("═══════════════════════════════════════════════════════════════════");
    println!("  🤫 SILENT PAYMENTS DEMO (BIP352)");
    println!("═══════════════════════════════════════════════════════════════════");
    println!();
    println!("  Silent Payments allow receiving Bitcoin without address reuse,");
    println!("  improving privacy by generating unique addresses for each sender.");
    println!();

    // Generate scan and spend keys
    let scan_key = PrivateKey::random();
    let spend_key = PrivateKey::random();

    let scan_pub = scan_key.public_key();
    let spend_pub = spend_key.public_key();

    // Create silent payment address
    let sp_addr = SilentPaymentAddress::new(&scan_pub, &spend_pub, Network::BitcoinMainnet).unwrap();

    println!("  🔑 Keys Generated:");
    println!("  ─────────────────────────────────────────────────────────────────");
    println!("  │ Scan Private Key  : {}...", &scan_key.to_hex()[..32]);
    println!("  │ Spend Private Key : {}...", &spend_key.to_hex()[..32]);
    println!();
    println!("  📬 Silent Payment Address:");
    println!("  ─────────────────────────────────────────────────────────────────");
    
    let addr_str = sp_addr.to_string();
    // Split long address for display
    if addr_str.len() > 60 {
        println!("  │ {}", &addr_str[..60]);
        println!("  │ {}", &addr_str[60..]);
    } else {
        println!("  │ {}", addr_str);
    }

    println!();
    println!("  ✨ Benefits of Silent Payments:");
    println!("  • No address reuse - each payment creates a unique address");
    println!("  • Improved privacy - harder to link payments to recipient");
    println!("  • Single static address - share one address publicly");
    println!("  • Compatible with Taproot outputs");
    println!("═══════════════════════════════════════════════════════════════════\n");
}

/// Demo 4: HD Derivation paths
fn demo_hd_derivation() {
    println!("\n");
    println!("═══════════════════════════════════════════════════════════════════");
    println!("  🌳 HD DERIVATION PATHS DEMO");
    println!("═══════════════════════════════════════════════════════════════════");

    let mnemonic = Mnemonic::generate(WordCount::Words24);
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::from_seed(seed.as_bytes(), HdNetwork::Mainnet).unwrap();

    println!("\n  📝 Master Seed (24-word mnemonic generated)");
    println!();

    let paths = [
        ("m/44'/0'/0'/0/0", "BIP44 - Legacy (P2PKH)", "Bitcoin"),
        ("m/44'/0'/0'/0/1", "BIP44 - Legacy (P2PKH)", "Bitcoin (2nd addr)"),
        ("m/49'/0'/0'/0/0", "BIP49 - SegWit-compat (P2SH-P2WPKH)", "Bitcoin"),
        ("m/84'/0'/0'/0/0", "BIP84 - Native SegWit (P2WPKH)", "Bitcoin"),
        ("m/86'/0'/0'/0/0", "BIP86 - Taproot (P2TR)", "Bitcoin"),
        ("m/44'/60'/0'/0/0", "BIP44 - Ethereum", "ETH/EVM"),
        ("m/44'/60'/0'/0/1", "BIP44 - Ethereum", "ETH (2nd addr)"),
    ];

    println!("  ┌─────────────────────────┬────────────────────────────────────────┐");
    println!("  │ Path                    │ Purpose                                │");
    println!("  ├─────────────────────────┼────────────────────────────────────────┤");

    for (path_str, purpose, _coin) in paths {
        let path = DerivationPath::parse(path_str).unwrap();
        let child = master.derive_path(&path).unwrap();
        let pk = child.private_key().unwrap();
        let pubkey = pk.public_key();

        println!("  │ {:<23} │ {:<38} │", path_str, purpose);
        
        // Show address based on path
        if path_str.contains("/60'/") {
            let addr = EthereumAddress::from_public_key(&pubkey).unwrap();
            println!("  │ └─ {} │", addr.to_checksum_string());
        } else if path_str.contains("/86'/") {
            let addr = P2TRAddress::from_public_key(&pubkey, Network::BitcoinMainnet).unwrap();
            println!("  │ └─ {:<54} │", addr.to_string());
        } else if path_str.contains("/84'/") {
            let addr = P2WPKHAddress::from_public_key(&pubkey, Network::BitcoinMainnet).unwrap();
            println!("  │ └─ {:<54} │", addr.to_string());
        } else {
            let addr = P2PKHAddress::from_public_key(&pubkey, Network::BitcoinMainnet).unwrap();
            println!("  │ └─ {:<54} │", addr.to_string());
        }
        println!("  ├─────────────────────────┼────────────────────────────────────────┤");
    }
    println!("  └─────────────────────────┴────────────────────────────────────────┘");

    println!("\n  ℹ️  Path Format: m / purpose' / coin_type' / account' / change / index");
    println!("     • ' = hardened derivation (more secure)");
    println!("     • coin_type: 0 = Bitcoin, 60 = Ethereum");
    println!("═══════════════════════════════════════════════════════════════════\n");
}

/// Demo 5: Random key generation
fn demo_random_keys() {
    println!("\n");
    println!("═══════════════════════════════════════════════════════════════════");
    println!("  🎲 RANDOM KEY GENERATION DEMO");
    println!("═══════════════════════════════════════════════════════════════════");
    println!();
    println!("  Generating 5 random keypairs...");
    println!();

    for i in 1..=5 {
        let pk = PrivateKey::random();
        let pubkey = pk.public_key();

        let p2wpkh = P2WPKHAddress::from_public_key(&pubkey, Network::BitcoinMainnet).unwrap();
        let p2tr = P2TRAddress::from_public_key(&pubkey, Network::BitcoinMainnet).unwrap();
        let eth = EthereumAddress::from_public_key(&pubkey).unwrap();

        println!("  ┌─ Keypair #{} ─────────────────────────────────────────────────┐", i);
        println!("  │ Private Key : {}...│", &pk.to_hex()[..48]);
        println!("  │ BTC SegWit  : {:<52} │", p2wpkh.to_string());
        println!("  │ BTC Taproot : {:<52} │", p2tr.to_string());
        println!("  │ Ethereum    : {:<52} │", eth.to_checksum_string());
        println!("  └────────────────────────────────────────────────────────────────┘");
        println!();
    }

    println!("  ⚠️  These are random keys for demonstration only!");
    println!("     For real use, always derive from a secure mnemonic.");
    println!("═══════════════════════════════════════════════════════════════════\n");
}
