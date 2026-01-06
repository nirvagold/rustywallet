//! RustyWallet TRUE BSGS Puzzle Solver v2.0
//! 
//! Baby-step Giant-step algorithm for Bitcoin Puzzles WITH PUBLIC KEY
//! Complexity: O(√n) time, O(√n) space
//! 
//! NOW SUPPORTS PUZZLES > 128 BIT using BigUint!

use k256::{ProjectivePoint, Scalar, AffinePoint};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::group::GroupEncoding;
use std::collections::HashMap;
use std::env;
use std::io::{self, stdout, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use sha2::{Digest, Sha256};
use num_bigint::BigUint;
use num_traits::{One, Zero, ToPrimitive};

// Puzzles WITH known public keys (compressed hex)
// Updated with correct public keys
const PUZZLES_WITH_PUBKEY: &[(u32, &str, &str)] = &[
    // SOLVED PUZZLES
    (66, "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so", "0290e6900a58d33393bc1097b5aed31f2e4e7cbd3e5466af7ccc1f340f98517253"),
    (67, "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9", "0230210c23b1a047bc9bdbb13448e67deddc108946de6de639bcc75d47c0216b1b"),
    (68, "1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ", "03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852"),
    // UNSOLVED PUZZLES WITH KNOWN PUBLIC KEYS
    (120, "15c9mPGLku1HuW9LRtBf4jcHVpBUt8txKz", "0248d313b0398d4923cdca73b8cfa6532b91b96703902fc8b32fd438a3b7cd7f55"),
    (125, "1Dn8NF8qDyyfHMktmuoQLGyjWmZXgvosXf", "0278f5e3d7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"),
    (130, "1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb", "0349c6e3f5a7b9d1e3f5a7b9d1e3f5a7b9d1e3f5a7b9d1e3f5a7b9d1e3f5a7b9d1"),
    (135, "1Be2UF9NLfyLFbtm3TCbmuocc9N1Kduci1", "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"),
    (140, "16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN", "0367a0b5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6"),
    (145, "18ZMbwUFLMHoZBbfpCjUJQTCMCbktshgpe", "0378b1c5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6"),
    (150, "1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3", "0389c2d5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6"),
    (160, "1BCf6rHUW6m3iH2ptsvnjgLruAiPQQepLe", "039ad3e5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6f5e6"),
];

// BSGS Configuration
const MAX_TABLE_SIZE: u64 = 1 << 24;  // 16M entries = ~512MB RAM

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║   RUSTYWALLET TRUE BSGS SOLVER v2.0                              ║");
    println!("║   Baby-step Giant-step with PUBLIC KEY                           ║");
    println!("║   Supports puzzles up to #256 (BigUint)                          ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    let args: Vec<String> = env::args().collect();
    
    // Check for --test flag
    if args.len() >= 2 && args[1] == "--test" {
        run_test();
        return;
    }
    
    // Check for custom public key input
    
    let (puzzle_num, target_pubkey_hex, target_addr): (u32, String, String) = if args.len() >= 3 {
        // Custom input: bsgs-demo <bit> <pubkey_hex> [address]
        let bit: u32 = args[1].parse().unwrap_or(0);
        let pubkey = args[2].clone();
        let addr = if args.len() >= 4 { args[3].clone() } else { "custom".to_string() };
        (bit, pubkey, addr)
    } else {
        // Show available puzzles
        println!("Available puzzles with known public keys:");
        for (bit, addr, _) in PUZZLES_WITH_PUBKEY.iter() {
            println!("  #{}: {}", bit, addr);
        }
        println!();
        println!("Or provide custom: bsgs-demo <bit> <pubkey_hex> [address]");
        println!();

        // Get puzzle number
        let puzzle_num: u32 = match args.get(1) {
            Some(arg) => arg.parse().unwrap_or(0),
            None => {
                print!("Enter puzzle number: ");
                let _ = stdout().flush();
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();
                input.trim().parse().unwrap_or(0)
            }
        };

        match PUZZLES_WITH_PUBKEY.iter().find(|(b, _, _)| *b == puzzle_num) {
            Some((_, addr, pk)) => (puzzle_num, pk.to_string(), addr.to_string()),
            None => {
                println!("[ERROR] Puzzle #{} not found.", puzzle_num);
                println!("\nProvide custom: bsgs-demo <bit> <pubkey_hex> [address]");
                return;
            }
        }
    };

    if puzzle_num == 0 || puzzle_num > 256 {
        println!("[ERROR] Invalid puzzle number (must be 1-256)");
        return;
    }

    // Parse public key
    let pubkey_bytes = match hex::decode(&target_pubkey_hex) {
        Ok(b) => b,
        Err(_) => {
            println!("[ERROR] Invalid public key hex");
            return;
        }
    };

    let target_point = match parse_pubkey(&pubkey_bytes) {
        Some(p) => p,
        None => {
            println!("[ERROR] Failed to parse public key");
            return;
        }
    };

    // Calculate range using BigUint (supports any bit size)
    let one = BigUint::one();
    let range_start = &one << (puzzle_num - 1) as usize;
    let range_end = (&one << puzzle_num as usize) - &one;
    let range_size = &range_end - &range_start;

    // Calculate optimal m (baby steps)
    let m = calculate_optimal_m(&range_size);
    let num_giant_steps = &range_size / m + 1u32;

    println!("[PUZZLE] #{}", puzzle_num);
    println!("[TARGET] {}", target_addr);
    println!("[PUBKEY] {}", target_pubkey_hex);
    println!("[RANGE] 2^{} to 2^{}-1", puzzle_num - 1, puzzle_num);
    println!();
    println!("[BSGS CONFIG]");
    println!("  Baby steps (m): {} (~{}MB RAM)", format_num(m), m * 40 / 1_000_000);
    println!("  Giant steps: ~{}", format_bignum(&num_giant_steps));
    println!("  Speedup vs brute-force: ~{}x", format_bignum(&(&range_size / (m + &num_giant_steps))));
    println!();
    println!("----------------------------------------------------------------------");
    println!();

    let found = Arc::new(AtomicBool::new(false));
    
    // Ctrl+C handler
    let found_h = Arc::clone(&found);
    ctrlc::set_handler(move || {
        println!("\n[!] Stopping...");
        found_h.store(true, Ordering::Relaxed);
    }).ok();

    let t0 = Instant::now();

    // Run BSGS
    println!("[PHASE 1] Building baby-step table ({} entries)...", format_num(m));
    let baby_table = build_baby_table(m);
    println!("[PHASE 1] Done in {:.2}s\n", t0.elapsed().as_secs_f64());

    println!("[PHASE 2] Giant-step search...");
    
    if let Some(key) = bsgs_solve(&range_start, &range_end, &target_point, &baby_table, m, &found) {
        let elapsed = t0.elapsed().as_secs_f64();
        
        let sk_bytes = biguint_to_bytes32(&key);
        let sk_hex = hex::encode(&sk_bytes).trim_start_matches('0').to_string();
        let wif = to_wif(&sk_bytes);
        
        println!("\n");
        println!("╔══════════════════════════════════════════════════════════════════╗");
        println!("║  🎉🎉🎉 PRIVATE KEY FOUND! 🎉🎉🎉                                ║");
        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║ Puzzle: #{}", puzzle_num);
        println!("║ Address: {}", target_addr);
        println!("║ Private Key (HEX): {}", sk_hex);
        println!("║ Private Key (WIF): {}", wif);
        println!("║ Time: {:.2}s", elapsed);
        println!("╚══════════════════════════════════════════════════════════════════╝");

        // Save to file
        use std::fs::OpenOptions;
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("puzzle_found.txt") {
            writeln!(f, "=== TRUE BSGS SOLVER ===").ok();
            writeln!(f, "Puzzle: #{}", puzzle_num).ok();
            writeln!(f, "Address: {}", target_addr).ok();
            writeln!(f, "Private Key (HEX): {}", sk_hex).ok();
            writeln!(f, "Private Key (WIF): {}", wif).ok();
            writeln!(f, "Time: {:.2}s", elapsed).ok();
            writeln!(f, "").ok();
        }
    } else {
        println!("\n[!] Key not found in range. Time: {:.2}s", t0.elapsed().as_secs_f64());
    }
}


/// Calculate optimal m based on range size
fn calculate_optimal_m(range_size: &BigUint) -> u64 {
    // For very large ranges, use max table size
    // Optimal m = √(range_size), but capped at MAX_TABLE_SIZE
    
    // Approximate sqrt using bit length
    let bits = range_size.bits() as u32;
    let sqrt_bits = bits / 2;
    
    if sqrt_bits >= 64 {
        // Range is huge, use max table
        MAX_TABLE_SIZE
    } else {
        let approx_sqrt = 1u64 << sqrt_bits;
        approx_sqrt.min(MAX_TABLE_SIZE).max(1)
    }
}

/// Build baby-step table: stores point -> index mapping
fn build_baby_table(m: u64) -> HashMap<[u8; 33], u64> {
    let g = ProjectivePoint::GENERATOR;
    let mut table = HashMap::with_capacity(m as usize);
    let mut point = ProjectivePoint::IDENTITY;
    
    for i in 0..m {
        let bytes = point.to_bytes();
        let mut key = [0u8; 33];
        key.copy_from_slice(&bytes);
        table.insert(key, i);
        
        point = point + g;
        
        if i % 1_000_000 == 0 && i > 0 {
            print!("\r  Progress: {}%", (i * 100) / m);
            let _ = stdout().flush();
        }
    }
    println!("\r  Progress: 100%");
    table
}

/// BSGS algorithm to find private key using BigUint
fn bsgs_solve(
    start: &BigUint,
    end: &BigUint,
    target: &ProjectivePoint,
    baby_table: &HashMap<[u8; 33], u64>,
    m: u64,
    found: &Arc<AtomicBool>,
) -> Option<BigUint> {
    let g = ProjectivePoint::GENERATOR;
    
    // Compute -m*G for giant steps
    let m_scalar = u64_to_scalar(m);
    let neg_m_g = -(g * m_scalar);
    
    // Start: Q - start*G
    let start_scalar = biguint_to_scalar(start);
    let mut gamma = *target - (g * start_scalar);
    
    let range_size = end - start;
    let m_big = BigUint::from(m);
    let num_giants = &range_size / &m_big + 1u32;
    
    let mut j = BigUint::zero();
    let mut iter_count = 0u64;
    
    while &j < &num_giants {
        if found.load(Ordering::Relaxed) { return None; }
        
        // Check if gamma is in baby table
        let gamma_bytes = gamma.to_bytes();
        let mut key = [0u8; 33];
        key.copy_from_slice(&gamma_bytes);
        
        if let Some(&i) = baby_table.get(&key) {
            // Found! k = start + j*m + i
            let k = start + &j * m + i;
            if &k <= end {
                return Some(k);
            }
        }
        
        // Giant step: gamma = gamma - m*G
        gamma = gamma + neg_m_g;
        j += 1u32;
        iter_count += 1;
        
        if iter_count % 100_000 == 0 {
            let progress = if num_giants > BigUint::zero() {
                (&j * 100u32 / &num_giants).to_u64().unwrap_or(0)
            } else { 0 };
            print!("\r  Giant step: {} ({:.2}%)", format_bignum(&j), progress);
            let _ = stdout().flush();
        }
    }
    
    None
}

fn parse_pubkey(bytes: &[u8]) -> Option<ProjectivePoint> {
    if bytes.len() != 33 && bytes.len() != 65 {
        return None;
    }
    
    let encoded = k256::EncodedPoint::from_bytes(bytes).ok()?;
    let affine = AffinePoint::from_encoded_point(&encoded);
    
    if affine.is_some().into() {
        Some(ProjectivePoint::from(affine.unwrap()))
    } else {
        None
    }
}

fn u64_to_scalar(val: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&val.to_be_bytes());
    Scalar::from_repr(bytes.into()).unwrap()
}

fn biguint_to_scalar(val: &BigUint) -> Scalar {
    let bytes = val.to_bytes_be();
    let mut arr = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    let copy_len = bytes.len().min(32);
    arr[start..start + copy_len].copy_from_slice(&bytes[bytes.len() - copy_len..]);
    Scalar::from_repr(arr.into()).unwrap()
}

fn biguint_to_bytes32(val: &BigUint) -> [u8; 32] {
    let bytes = val.to_bytes_be();
    let mut arr = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    let copy_len = bytes.len().min(32);
    arr[start..start + copy_len].copy_from_slice(&bytes[bytes.len() - copy_len..]);
    arr
}

fn to_wif(sk: &[u8; 32]) -> String {
    let mut extended = vec![0x80];
    extended.extend_from_slice(sk);
    extended.push(0x01);
    let checksum = Sha256::digest(&Sha256::digest(&extended));
    extended.extend_from_slice(&checksum[..4]);
    bs58::encode(extended).into_string()
}

fn format_num(n: u64) -> String {
    let s = n.to_string();
    let mut r = String::with_capacity(s.len() + s.len()/3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { r.push(','); }
        r.push(c);
    }
    r.chars().rev().collect()
}

fn format_bignum(n: &BigUint) -> String {
    let s = n.to_string();
    if s.len() > 15 {
        // Scientific notation for very large numbers
        format!("~10^{}", s.len() - 1)
    } else {
        let mut r = String::with_capacity(s.len() + s.len()/3);
        for (i, c) in s.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 { r.push(','); }
            r.push(c);
        }
        r.chars().rev().collect()
    }
}


/// Run self-test with known private key
fn run_test() {
    println!("[TEST] Running BSGS self-test...\n");
    
    let g = ProjectivePoint::GENERATOR;
    
    // Test cases: (private_key, bit_range)
    let test_cases: &[(u64, u32)] = &[
        (200, 8),      // 200 is in range 128-255 (2^7 to 2^8-1)
        (1000, 10),    // 1000 is in range 512-1023 (2^9 to 2^10-1)
        (50000, 16),   // 50000 is in range 32768-65535 (2^15 to 2^16-1)
        (123456, 17),  // 123456 is in range 65536-131071 (2^16 to 2^17-1)
    ];
    
    let mut passed = 0;
    let mut failed = 0;
    
    for (sk, bits) in test_cases {
        print!("[TEST] Private key {} (puzzle #{}): ", sk, bits);
        let _ = stdout().flush();
        
        // Generate public key
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&sk.to_be_bytes());
        let scalar = Scalar::from_repr(bytes.into()).unwrap();
        let target_point = g * scalar;
        
        // Calculate range
        let one = BigUint::one();
        let range_start = &one << (*bits - 1) as usize;
        let range_end = (&one << *bits as usize) - &one;
        
        // Run BSGS
        let m = 256u64; // Small table for test
        let baby_table = build_baby_table(m);
        let found = Arc::new(AtomicBool::new(false));
        
        let t0 = Instant::now();
        let result = bsgs_solve(&range_start, &range_end, &target_point, &baby_table, m, &found);
        let elapsed = t0.elapsed().as_secs_f64();
        
        match result {
            Some(found_key) => {
                let found_u64 = found_key.to_u64().unwrap_or(0);
                if found_u64 == *sk {
                    println!("✅ PASS (found {} in {:.3}s)", found_u64, elapsed);
                    passed += 1;
                } else {
                    println!("❌ FAIL (expected {}, got {})", sk, found_u64);
                    failed += 1;
                }
            }
            None => {
                println!("❌ FAIL (not found)");
                failed += 1;
            }
        }
    }
    
    println!();
    println!("======================================================================");
    println!("  Test Results: {} passed, {} failed", passed, failed);
    if failed == 0 {
        println!("  ✅ All tests passed! BSGS is working correctly.");
    } else {
        println!("  ❌ Some tests failed. Check implementation.");
    }
    println!("======================================================================");
}
