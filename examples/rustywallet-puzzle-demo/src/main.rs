//! RustyWallet Puzzle Solver v1.0
//! Bitcoin Puzzle brute-force with Xieve-like modular filtering
//! 
//! Usage: Set TARGET_ADDRESS and RANGE_START/RANGE_END below

use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use std::io::{stdout, Write};
use std::sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc};
use std::thread;
use std::time::{Duration, Instant};
use k256::{ProjectivePoint, Scalar, AffinePoint};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;

// ============================================================================
// CONFIGURATION - Edit these values for your puzzle
// ============================================================================

// Target address to find (P2PKH format starting with '1')
// Example: Bitcoin Puzzle #66
const TARGET_ADDRESS: &str = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so";

// Private key range (hex) - Puzzle #66 range
// Range: 2^65 to 2^66-1
const RANGE_START: &str = "20000000000000000"; // 2^65
const RANGE_END: &str = "3ffffffffffffffff";   // 2^66-1

// Xieve modulus - product of small primes for filtering
// Higher = more filtering but may miss keys
// Set to 1 to disable filtering
const XIEVE_MODULUS: u64 = 1; // Disabled by default (safe mode)

// Number of threads (0 = auto-detect)
const THREADS: usize = 0;

// ============================================================================
// END CONFIGURATION
// ============================================================================

const BATCH_SIZE: usize = 50_000;
const UPDATE_INTERVAL: usize = 10_000;

fn main() {
    let threads = if THREADS == 0 { num_cpus::get_physical().max(2) } else { THREADS };
    
    println!("\n======================================================================");
    println!("     RUSTYWALLET PUZZLE SOLVER v1.0");
    println!("======================================================================\n");
    
    // Parse target address to hash160
    let target_h160 = match decode_address(TARGET_ADDRESS) {
        Some(h) => h,
        None => {
            println!("[ERROR] Invalid target address: {}", TARGET_ADDRESS);
            return;
        }
    };
    
    println!("[TARGET] {}", TARGET_ADDRESS);
    println!("[HASH160] {}", hex::encode(&target_h160));
    
    // Parse range
    let start = match parse_hex_to_bytes(RANGE_START) {
        Some(b) => b,
        None => {
            println!("[ERROR] Invalid RANGE_START");
            return;
        }
    };
    let end = match parse_hex_to_bytes(RANGE_END) {
        Some(b) => b,
        None => {
            println!("[ERROR] Invalid RANGE_END");
            return;
        }
    };
    
    println!("[RANGE] {} - {}", RANGE_START, RANGE_END);
    
    // Calculate range size
    let range_bits = estimate_range_bits(&start, &end);
    println!("[BITS] ~{} bits", range_bits);
    
    if XIEVE_MODULUS > 1 {
        println!("[XIEVE] Modulus = {} (filtering enabled)", XIEVE_MODULUS);
    } else {
        println!("[XIEVE] Disabled (checking all keys)");
    }
    
    println!("[THREADS] {}", threads);
    println!();
    println!("----------------------------------------------------------------------");
    
    let target_h160 = Arc::new(target_h160);
    let att = Arc::new(AtomicU64::new(0));
    let run = Arc::new(AtomicBool::new(true));
    let found = Arc::new(AtomicBool::new(false));
    
    let t0 = Instant::now();
    let mut handles = vec![];
    
    // Divide range among threads
    let range_per_thread = divide_range(&start, &end, threads);
    
    for (i, (thread_start, thread_end)) in range_per_thread.into_iter().enumerate() {
        let target = Arc::clone(&target_h160);
        let att_c = Arc::clone(&att);
        let run_c = Arc::clone(&run);
        let found_c = Arc::clone(&found);
        
        handles.push(thread::spawn(move || {
            worker(i, thread_start, thread_end, target, att_c, run_c, found_c);
        }));
    }
    
    // Reporter thread
    let att_r = Arc::clone(&att);
    let run_r = Arc::clone(&run);
    let found_r = Arc::clone(&found);
    thread::spawn(move || {
        let mut last = 0u64;
        loop {
            thread::sleep(Duration::from_secs(2));
            if !run_r.load(Ordering::Relaxed) || found_r.load(Ordering::Relaxed) { break; }
            let cur = att_r.load(Ordering::Relaxed);
            let spd = cur.saturating_sub(last) / 2;
            last = cur;
            print!("\r[SCANNING] {} keys | {}/s | {}s   ",
                fmt(cur), fmt(spd), t0.elapsed().as_secs());
            let _ = stdout().flush();
        }
    });
    
    // Ctrl+C handler
    let run_h = Arc::clone(&run);
    ctrlc::set_handler(move || {
        println!("\n[!] Stopping...");
        run_h.store(false, Ordering::Relaxed);
    }).ok();
    
    // Wait for all threads
    for h in handles {
        h.join().ok();
    }
    
    let total = att.load(Ordering::Relaxed);
    let elapsed = t0.elapsed().as_secs_f64();
    
    println!("\n\n======================================================================");
    if found.load(Ordering::Relaxed) {
        println!("  🎉 PRIVATE KEY FOUND! Check output above.");
    } else {
        println!("  ❌ Not found in range. {} keys @ {}/s", fmt(total), fmt((total as f64/elapsed) as u64));
    }
    println!("======================================================================");
}

fn worker(id: usize, start: [u8; 32], end: [u8; 32], target: Arc<[u8; 20]>,
          att: Arc<AtomicU64>, run: Arc<AtomicBool>, found: Arc<AtomicBool>) {
    
    let g = ProjectivePoint::GENERATOR;
    let mut h160 = [0u8; 20];
    let mut la = 0u64;
    
    // Initialize scalar from start
    let mut scalar: Scalar = match Scalar::from_repr(start.into()).into_option() {
        Some(s) => s,
        None => return,
    };
    let end_scalar: Scalar = match Scalar::from_repr(end.into()).into_option() {
        Some(s) => s,
        None => return,
    };
    
    let mut point: ProjectivePoint = g * scalar;
    
    // Convert to u64 for Xieve check (only works for small ranges)
    let mut key_u64: u64 = bytes_to_u64(&start);
    
    loop {
        if !run.load(Ordering::Relaxed) || found.load(Ordering::Relaxed) { break; }
        
        for _ in 0..BATCH_SIZE {
            // Check if we've exceeded the range
            if scalar.to_repr() > end_scalar.to_repr() {
                att.fetch_add(la, Ordering::Relaxed);
                return;
            }
            
            // Xieve filter - skip keys that don't match modular condition
            if XIEVE_MODULUS > 1 && (key_u64 % XIEVE_MODULUS) != 0 {
                point = point + g;
                scalar = scalar + Scalar::ONE;
                key_u64 = key_u64.wrapping_add(1);
                continue;
            }
            
            // Compute public key and hash160
            let affine: AffinePoint = point.into();
            let enc = affine.to_encoded_point(true);
            let pk_bytes = enc.as_bytes();
            
            if pk_bytes.len() == 33 {
                // Hash160
                let sha = Sha256::digest(pk_bytes);
                let rip = Ripemd160::digest(&sha);
                h160.copy_from_slice(&rip);
                
                // Check match
                if h160 == *target {
                    found.store(true, Ordering::Relaxed);
                    run.store(false, Ordering::Relaxed);
                    
                    let sk_bytes: [u8; 32] = scalar.to_repr().into();
                    let sk_hex = hex::encode(&sk_bytes);
                    
                    // Generate WIF
                    let wif = to_wif(&sk_bytes);
                    
                    println!("\n");
                    println!("╔══════════════════════════════════════════════════════════════════╗");
                    println!("║  🎉🎉🎉 PRIVATE KEY FOUND! 🎉🎉🎉                                ║");
                    println!("╠══════════════════════════════════════════════════════════════════╣");
                    println!("║ Thread: {}                                                        ", id);
                    println!("║ Address: {}              ", TARGET_ADDRESS);
                    println!("║ Private Key (HEX): {}    ", sk_hex.trim_start_matches('0'));
                    println!("║ Private Key (WIF): {}    ", wif);
                    println!("╚══════════════════════════════════════════════════════════════════╝");
                    
                    // Save to file
                    use std::fs::OpenOptions;
                    use std::io::Write;
                    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("puzzle_found.txt") {
                        writeln!(f, "Address: {}", TARGET_ADDRESS).ok();
                        writeln!(f, "Private Key (HEX): {}", sk_hex).ok();
                        writeln!(f, "Private Key (WIF): {}", wif).ok();
                        writeln!(f, "").ok();
                    }
                    
                    return;
                }
            }
            
            la += 1;
            point = point + g;
            scalar = scalar + Scalar::ONE;
            key_u64 = key_u64.wrapping_add(1);
            
            if la % UPDATE_INTERVAL as u64 == 0 {
                att.fetch_add(la, Ordering::Relaxed);
                la = 0;
                if !run.load(Ordering::Relaxed) { return; }
            }
        }
    }
    att.fetch_add(la, Ordering::Relaxed);
}

fn decode_address(addr: &str) -> Option<[u8; 20]> {
    if !addr.starts_with('1') { return None; }
    let decoded = bs58::decode(addr).into_vec().ok()?;
    if decoded.len() != 25 { return None; }
    let mut h160 = [0u8; 20];
    h160.copy_from_slice(&decoded[1..21]);
    Some(h160)
}

fn parse_hex_to_bytes(hex_str: &str) -> Option<[u8; 32]> {
    let hex_clean = hex_str.trim_start_matches("0x");
    let padded = format!("{:0>64}", hex_clean);
    let bytes = hex::decode(&padded).ok()?;
    if bytes.len() != 32 { return None; }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

fn bytes_to_u64(bytes: &[u8; 32]) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[24..32]);
    u64::from_be_bytes(arr)
}

fn estimate_range_bits(start: &[u8; 32], end: &[u8; 32]) -> u32 {
    for i in 0..32 {
        if end[i] != 0 {
            return (32 - i) as u32 * 8 - end[i].leading_zeros();
        }
    }
    0
}

fn divide_range(start: &[u8; 32], end: &[u8; 32], threads: usize) -> Vec<([u8; 32], [u8; 32])> {
    // Simple division - just split the range evenly
    // For proper implementation, use big integer arithmetic
    let mut ranges = vec![];
    
    // For now, just give each thread the full range offset by thread_id
    // This is a simplified approach
    for i in 0..threads {
        let mut thread_start = *start;
        // Add offset based on thread id
        let offset = i as u64;
        let mut carry = offset;
        for j in (0..32).rev() {
            let sum = thread_start[j] as u64 + (carry % 256);
            thread_start[j] = (sum % 256) as u8;
            carry = sum / 256 + carry / 256;
            if carry == 0 { break; }
        }
        ranges.push((thread_start, *end));
    }
    ranges
}

fn to_wif(sk: &[u8; 32]) -> String {
    let mut extended = vec![0x80]; // Mainnet prefix
    extended.extend_from_slice(sk);
    extended.push(0x01); // Compressed
    let checksum = Sha256::digest(&Sha256::digest(&extended));
    extended.extend_from_slice(&checksum[..4]);
    bs58::encode(extended).into_string()
}

fn fmt(n: u64) -> String {
    let s = n.to_string();
    let mut r = String::with_capacity(s.len() + s.len()/3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { r.push(','); }
        r.push(c);
    }
    r.chars().rev().collect()
}
