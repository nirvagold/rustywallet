//! RustyWallet Pollard Kangaroo Solver v2.0
//! 
//! Multi-threaded Pollard's Kangaroo algorithm for Bitcoin Puzzle solving
//! Complexity: O(√n) time, O(1) space - perfect for large puzzles!
//! 
//! Supports puzzles up to #256 using BigUint

use k256::{ProjectivePoint, Scalar, AffinePoint};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::group::GroupEncoding;
use std::collections::HashMap;
use std::env;
use std::io::{stdout, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::thread;
use sha2::{Digest, Sha256};
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};

// Number of jump distances (power of 2 for efficiency)
const NUM_JUMPS: usize = 32;

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║   RUSTYWALLET POLLARD KANGAROO SOLVER v2.0                       ║");
    println!("║   Multi-threaded O(√n) time, O(1) space                          ║");
    println!("║   Supports puzzles up to #256 (BigUint)                          ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    let args: Vec<String> = env::args().collect();
    
    if args.len() >= 2 && args[1] == "--test" {
        run_test();
        return;
    }
    
    if args.len() >= 3 && args[1] == "--genkey" {
        generate_pubkey(&args[2]);
        return;
    }
    
    let (puzzle_num, target_pubkey_hex, target_addr): (u32, String, String) = if args.len() >= 3 {
        let bit: u32 = args[1].parse().unwrap_or(0);
        let pubkey = args[2].clone();
        let addr = if args.len() >= 4 { args[3].clone() } else { "custom".to_string() };
        (bit, pubkey, addr)
    } else {
        println!("Usage: kangaroo-demo <bit> <pubkey_hex> [address]");
        println!("       kangaroo-demo --test");
        println!("       kangaroo-demo --genkey <privkey_hex>");
        return;
    };

    if puzzle_num == 0 || puzzle_num > 256 {
        println!("[ERROR] Invalid puzzle number (must be 1-256)");
        return;
    }

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

    let one = BigUint::one();
    let range_start = &one << (puzzle_num - 1) as usize;
    let range_end = (&one << puzzle_num as usize) - &one;
    let range_size = &range_end - &range_start;

    let expected_ops = BigUint::from(2u32) * sqrt_biguint(&range_size);
    let range_bits = range_size.bits() as u32;
    let dp_bits = (range_bits / 4).max(4).min(20);
    let num_threads = num_cpus::get_physical().max(1).min(8);

    println!("[PUZZLE] #{}", puzzle_num);
    println!("[TARGET] {}", target_addr);
    println!("[PUBKEY] {}", target_pubkey_hex);
    println!("[RANGE] 2^{} to 2^{}-1", puzzle_num - 1, puzzle_num);
    println!();
    println!("[KANGAROO CONFIG]");
    println!("  Threads: {}", num_threads);
    println!("  Jump table size: {}", NUM_JUMPS);
    println!("  DP bits: {} (1 in {} points)", dp_bits, 1u64 << dp_bits);
    println!("  Expected operations: ~{}", format_bignum(&expected_ops));
    println!();
    println!("----------------------------------------------------------------------");
    println!();

    let found = Arc::new(AtomicBool::new(false));
    
    let found_h = Arc::clone(&found);
    ctrlc::set_handler(move || {
        println!("\n[!] Stopping...");
        found_h.store(true, Ordering::Relaxed);
    }).ok();

    let t0 = Instant::now();

    if let Some(key) = kangaroo_solve_mt(&range_start, &range_end, &target_point, &found, num_threads) {
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

        use std::fs::OpenOptions;
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("puzzle_found.txt") {
            writeln!(f, "=== KANGAROO SOLVER ===").ok();
            writeln!(f, "Puzzle: #{}", puzzle_num).ok();
            writeln!(f, "Address: {}", target_addr).ok();
            writeln!(f, "Private Key (HEX): {}", sk_hex).ok();
            writeln!(f, "Private Key (WIF): {}", wif).ok();
            writeln!(f, "Time: {:.2}s", elapsed).ok();
            writeln!(f, "").ok();
        }
    } else {
        println!("\n[!] Search stopped. Time: {:.2}s", t0.elapsed().as_secs_f64());
    }
}


/// Multi-threaded Kangaroo solver
/// Each thread runs its own tame+wild kangaroo pair
/// All threads share a common DP table for collision detection
fn kangaroo_solve_mt(
    start: &BigUint,
    end: &BigUint,
    target: &ProjectivePoint,
    found: &Arc<AtomicBool>,
    num_threads: usize,
) -> Option<BigUint> {
    let g = ProjectivePoint::GENERATOR;
    let range_size = end - start;
    
    let range_bits = range_size.bits() as u32;
    let dp_bits = (range_bits / 4).max(4).min(20);
    let dp_mask = (1u64 << dp_bits) - 1;
    
    // Mean jump size
    let mean_jump = sqrt_biguint(&range_size) / NUM_JUMPS as u32;
    
    // Build jump table
    println!("[PHASE 1] Building jump table...");
    let mut jump_distances: Vec<BigUint> = Vec::with_capacity(NUM_JUMPS);
    let mut jump_points: Vec<ProjectivePoint> = Vec::with_capacity(NUM_JUMPS);
    
    for i in 0..NUM_JUMPS {
        let shift = (i as i32) - (NUM_JUMPS as i32 / 2);
        let dist = if shift >= 0 {
            &mean_jump << (shift as usize)
        } else {
            &mean_jump >> ((-shift) as usize)
        };
        let dist = dist.max(BigUint::one());
        
        let scalar = biguint_to_scalar(&dist);
        let point = g * scalar;
        
        jump_distances.push(dist);
        jump_points.push(point);
    }
    println!("[PHASE 1] Done. Mean jump: ~2^{}", mean_jump.bits());
    println!();
    
    // Shared state
    let dp_table: Arc<Mutex<HashMap<[u8; 8], (BigUint, bool)>>> = Arc::new(Mutex::new(HashMap::new()));
    let ops_counter = Arc::new(AtomicU64::new(0));
    let result: Arc<Mutex<Option<BigUint>>> = Arc::new(Mutex::new(None));
    
    let jump_distances = Arc::new(jump_distances);
    let jump_points = Arc::new(jump_points);
    let start = Arc::new(start.clone());
    let end = Arc::new(end.clone());
    let target = Arc::new(*target);
    
    println!("[PHASE 2] Running {} kangaroo pairs...", num_threads);
    
    let t0 = Instant::now();
    
    // Spawn worker threads
    let mut handles = vec![];
    
    for tid in 0..num_threads {
        let found = Arc::clone(found);
        let dp_table = Arc::clone(&dp_table);
        let ops_counter = Arc::clone(&ops_counter);
        let result = Arc::clone(&result);
        let jump_distances = Arc::clone(&jump_distances);
        let jump_points = Arc::clone(&jump_points);
        let start = Arc::clone(&start);
        let end = Arc::clone(&end);
        let target = Arc::clone(&target);
        let range_size = range_size.clone();
        
        let handle = thread::spawn(move || {
            kangaroo_worker(
                tid, &start, &end, &target, &range_size,
                &jump_distances, &jump_points,
                dp_mask, &dp_table, &ops_counter, &result, &found
            );
        });
        
        handles.push(handle);
    }
    
    // Progress monitor in main thread
    let total_ops = ops_counter.clone();
    let found_monitor = found.clone();
    let result_monitor = result.clone();
    
    loop {
        thread::sleep(std::time::Duration::from_millis(500));
        
        if found_monitor.load(Ordering::Relaxed) {
            break;
        }
        
        let ops = total_ops.load(Ordering::Relaxed);
        let elapsed = t0.elapsed().as_secs_f64();
        let rate = ops as f64 / elapsed.max(0.001);
        let dp_count = dp_table.lock().unwrap().len();
        
        print!("\r  Operations: {} | Rate: {:.0} ops/s | DPs: {}   ", 
            format_num(ops), rate, dp_count);
        let _ = stdout().flush();
        
        // Check if found
        if result_monitor.lock().unwrap().is_some() {
            found_monitor.store(true, Ordering::Relaxed);
            break;
        }
    }
    
    // Wait for all threads
    for handle in handles {
        handle.join().ok();
    }
    
    // Return result
    let res = result.lock().unwrap().clone();
    res
}

fn kangaroo_worker(
    tid: usize,
    start: &BigUint,
    end: &BigUint,
    target: &ProjectivePoint,
    range_size: &BigUint,
    jump_distances: &[BigUint],
    jump_points: &[ProjectivePoint],
    dp_mask: u64,
    dp_table: &Arc<Mutex<HashMap<[u8; 8], (BigUint, bool)>>>,
    ops_counter: &Arc<AtomicU64>,
    result: &Arc<Mutex<Option<BigUint>>>,
    found: &Arc<AtomicBool>,
) {
    let g = ProjectivePoint::GENERATOR;
    
    // Each thread starts at different position
    // Tame: start + range_size * (tid + 1) / (num_threads + 1)
    let offset = range_size * (tid as u32 + 1) / 8u32;
    let tame_start_dist = offset.clone();
    let tame_start_scalar = biguint_to_scalar(&(start + &tame_start_dist));
    let mut tame_pos = g * tame_start_scalar;
    let mut tame_dist = tame_start_dist;
    
    // Wild starts at target
    let mut wild_pos = *target;
    let mut wild_dist = BigUint::from(0u32);
    
    let mut local_ops = 0u64;
    
    loop {
        if found.load(Ordering::Relaxed) {
            return;
        }
        
        // Batch update ops counter
        local_ops += 2;
        if local_ops >= 10000 {
            ops_counter.fetch_add(local_ops, Ordering::Relaxed);
            local_ops = 0;
        }
        
        // === TAME KANGAROO ===
        let tame_jump_idx = get_jump_index(&tame_pos);
        tame_pos = tame_pos + jump_points[tame_jump_idx];
        tame_dist = &tame_dist + &jump_distances[tame_jump_idx];
        
        if is_distinguished_point(&tame_pos, dp_mask) {
            let hash = point_hash(&tame_pos);
            
            let mut table = dp_table.lock().unwrap();
            
            // Check collision with wild
            if let Some((wild_d, false)) = table.get(&hash) {
                if &tame_dist > wild_d {
                    let key = start + &tame_dist - wild_d;
                    if &key >= start && &key <= end {
                        let key_scalar = biguint_to_scalar(&key);
                        let computed = g * key_scalar;
                        if computed == *target {
                            *result.lock().unwrap() = Some(key);
                            found.store(true, Ordering::Relaxed);
                            return;
                        }
                    }
                }
            }
            
            table.insert(hash, (tame_dist.clone(), true));
        }
        
        // === WILD KANGAROO ===
        let wild_jump_idx = get_jump_index(&wild_pos);
        wild_pos = wild_pos + jump_points[wild_jump_idx];
        wild_dist = &wild_dist + &jump_distances[wild_jump_idx];
        
        if is_distinguished_point(&wild_pos, dp_mask) {
            let hash = point_hash(&wild_pos);
            
            let mut table = dp_table.lock().unwrap();
            
            // Check collision with tame
            if let Some((tame_d, true)) = table.get(&hash) {
                if tame_d > &wild_dist {
                    let key = start + tame_d - &wild_dist;
                    if &key >= start && &key <= end {
                        let key_scalar = biguint_to_scalar(&key);
                        let computed = g * key_scalar;
                        if computed == *target {
                            *result.lock().unwrap() = Some(key);
                            found.store(true, Ordering::Relaxed);
                            return;
                        }
                    }
                }
            }
            
            table.insert(hash, (wild_dist.clone(), false));
        }
    }
}

fn get_jump_index(point: &ProjectivePoint) -> usize {
    let bytes = point.to_bytes();
    (bytes[32] as usize) % NUM_JUMPS
}

fn is_distinguished_point(point: &ProjectivePoint, mask: u64) -> bool {
    let bytes = point.to_bytes();
    let val = u64::from_le_bytes([
        bytes[25], bytes[26], bytes[27], bytes[28],
        bytes[29], bytes[30], bytes[31], bytes[32],
    ]);
    (val & mask) == 0
}

fn point_hash(point: &ProjectivePoint) -> [u8; 8] {
    let bytes = point.to_bytes();
    let mut hash = [0u8; 8];
    hash.copy_from_slice(&bytes[1..9]);
    hash
}

fn sqrt_biguint(n: &BigUint) -> BigUint {
    if n.bits() == 0 {
        return BigUint::from(0u32);
    }
    let bits = n.bits() as usize;
    let mut x = BigUint::one() << (bits / 2);
    loop {
        let x_new = (&x + n / &x) / 2u32;
        if x_new >= x {
            return x;
        }
        x = x_new;
    }
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
        format!("~2^{}", n.bits())
    } else {
        let mut r = String::with_capacity(s.len() + s.len()/3);
        for (i, c) in s.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 { r.push(','); }
            r.push(c);
        }
        r.chars().rev().collect()
    }
}

fn run_test() {
    println!("[TEST] Running Kangaroo self-test...\n");
    
    let g = ProjectivePoint::GENERATOR;
    let test_cases: &[(u64, u32)] = &[
        (200, 8),
        (1000, 10),
        (50000, 16),
    ];
    
    let mut passed = 0;
    let mut failed = 0;
    
    for (sk, bits) in test_cases {
        print!("[TEST] Private key {} (puzzle #{}): ", sk, bits);
        let _ = stdout().flush();
        
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&sk.to_be_bytes());
        let scalar = Scalar::from_repr(bytes.into()).unwrap();
        let target_point = g * scalar;
        
        let one = BigUint::one();
        let range_start = &one << (*bits - 1) as usize;
        let range_end = (&one << *bits as usize) - &one;
        
        let found = Arc::new(AtomicBool::new(false));
        
        let t0 = Instant::now();
        let result = kangaroo_solve_mt(&range_start, &range_end, &target_point, &found, 4);
        let elapsed = t0.elapsed().as_secs_f64();
        
        match result {
            Some(found_key) => {
                let found_u64 = found_key.to_u64().unwrap_or(0);
                if found_u64 == *sk {
                    println!("\n✅ PASS (found {} in {:.3}s)", found_u64, elapsed);
                    passed += 1;
                } else {
                    println!("\n❌ FAIL (expected {}, got {})", sk, found_u64);
                    failed += 1;
                }
            }
            None => {
                println!("\n❌ FAIL (not found)");
                failed += 1;
            }
        }
    }
    
    println!();
    println!("======================================================================");
    println!("  Test Results: {} passed, {} failed", passed, failed);
    if failed == 0 {
        println!("  ✅ All tests passed!");
    }
    println!("======================================================================");
}

fn generate_pubkey(privkey_hex: &str) {
    println!("[GENKEY] Generating public key from private key...\n");
    
    let privkey_hex = privkey_hex.trim_start_matches("0x");
    let padded = format!("{:0>64}", privkey_hex);
    
    let bytes = match hex::decode(&padded) {
        Ok(b) => b,
        Err(_) => {
            println!("[ERROR] Invalid hex");
            return;
        }
    };
    
    if bytes.len() != 32 {
        println!("[ERROR] Private key must be 32 bytes");
        return;
    }
    
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    
    let scalar = match Scalar::from_repr(arr.into()).into_option() {
        Some(s) => s,
        None => {
            println!("[ERROR] Invalid scalar");
            return;
        }
    };
    
    let g = ProjectivePoint::GENERATOR;
    let pubkey_point = g * scalar;
    let pubkey_bytes = pubkey_point.to_bytes();
    
    println!("Private Key (HEX): {}", privkey_hex);
    println!("Public Key (Compressed): {}", hex::encode(&pubkey_bytes));
    println!();
    println!("Use this public key with Kangaroo:");
    println!("  kangaroo-demo <bit> {} [address]", hex::encode(&pubkey_bytes));
}
