//! RustyWallet Puzzle Solver v4.0 - WITH XIEVE FILTERING
//! Bitcoin Puzzle brute-force solver (Puzzle #57 - #100)
//! Implements Xieve-like modular sieve for faster scanning

use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use std::env;
use std::io::{self, stdout, Write};
use std::sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc};
use std::thread;
use std::time::{Duration, Instant};
use k256::{ProjectivePoint, Scalar};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::GroupEncoding;

// ============================================================================
// XIEVE CONFIGURATION
// ============================================================================
// Xieve uses modular arithmetic to skip "impossible" keys
// Based on the observation that valid keys often follow patterns
// 
// SIEVE_MODULUS: Product of small primes (2 * 3 * 5 * 7 = 210)
// This allows skipping ~99.5% of keys that are statistically unlikely
// Set to 1 to disable (check all keys)
// 
// WARNING: Xieve filtering may skip the actual key if the pattern
// assumption is wrong. Use with caution!
// ============================================================================
const DEFAULT_SIEVE_ENABLED: bool = true;  // Default: Xieve enabled
const SIEVE_MODULUS: u64 = 210;     // 2*3*5*7 - skip keys not divisible
const SIEVE_REMAINDER: u64 = 0;     // Only check keys where k % MODULUS == REMAINDER

// Puzzle database: (bit, address)
// Hash160 is decoded from address at runtime for accuracy
const PUZZLES: &[(u32, &str)] = &[
    (57, "1BDyrQ6WoF8VN3g9SAS1iKZcPzFfnDVieY"),
    (58, "1HduPEXZRdG26SUT5Yk83mLkPyjnZuJ7Bm"),
    (59, "1GnNTmTVLZiqQfLbAdp9DVdicEnB5GoERE"),
    (60, "1NWmZRpHH4XSPwsW6dsS3nrNWfL1yrJj4w"),
    (61, "1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum"),
    (62, "14oFNXucftsHiUMY8uctg6N487riuyXs4h"),
    (63, "1CfZWK1QTQE3eS9qn61dQjV89KDjZzfNcv"),
    (64, "1L2GM8eE7mJWLdo3HZS6su1832NX2txaac"),
    (65, "1rSnXMr63jdCuegJFuidJqWxUPV7AtUf7"),
    (66, "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"),
    (67, "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9"),
    (68, "1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ"),
    (69, "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG"),
    (70, "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR"),
    (71, "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"),
    (72, "1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR"),
    (73, "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4"),
    (74, "1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv"),
    (75, "1J36UjUByGroXcCvmj13U6uwaVv9caEeAt"),
    (76, "1DJh2eHFYQfACPmrvpyWc8MSTYKh7w9eRF"),
    (77, "1Bxk4CQdqL9p22JEtDfdXMsng1XacifUtE"),
    (78, "15qF6X51huDjqTmF9BJgxXdt1xcj46Jmhb"),
    (79, "1ARk8HWJMn8js8tQmGUJeQHjSE7KRkn2t8"),
    (80, "15qsCm78whspNQFydGJQk5rexzxTQopnHZ"),
    (81, "13zYrYhhJxp6Ui1VV7pqa5WDhNWM45ARAC"),
    (82, "14MdEb4eFcT3MVG5sPFG4jGLuHJSnt1Dk2"),
    (83, "1CMq3SvFcVEcpLMuuH8PUcNiqsK1oicG2D"),
    (84, "1Kh22PvXERd2xpTQk3ur6pPEqFeckCJfAr"),
    (85, "1K3x5L6G57Y494fDqBfrojD28UJv4s5JcK"),
    (86, "1PxH3K1Shdjb7gSEoTX7UPDZ6SH4qGPrvq"),
    (87, "16AbnZjZZipwHMkYKBSfswGWKDmXHjEpSf"),
    (88, "19QciEHbGVNY4hrhfKXmcBBCrJSBZ6TaVt"),
    (89, "1L12FHH2FHjvTviyanuiFVfmzCy46RRATU"),
    (90, "1EzVHtmbN4fs4MiNk3ppEnKKhsmXYJ4s74"),
    (91, "1AE8NzzgKE7Yhz7BWtAcAAxiFMbPo82NB5"),
    (92, "17Q7tuG2JwFFU9rXVj3uZqRtioH3mx2Jad"),
    (93, "1K6xGMUbs6ZTXBnhw1pippqwK6wjBWtNpL"),
    (94, "19eVSDuizydXxhohGh8Ki9WY9KsHdSwoQC"),
    (95, "15ANYzzCp5BFHcCnVFzXqyibpzgPLWaD8b"),
    (96, "18ywPwj39nGjqBrQJSzZVq2izR12MDpDr8"),
    (97, "1CaBVPrwUxbQYYswu32w7Mj4HR4maNoJSX"),
    (98, "1JWnE6p6UN7ZJBN7TtcbNDoRcjFtuDWoNL"),
    (99, "1KCgMv8fo2TPBpddVi9jqmMmcne9uSNJ5F"),
    (100, "1HLgpNrLTLqYqEiUWECkUFMNbFqsXv3VLF"),
];

const BATCH_SIZE: usize = 100_000;
const UPDATE_INTERVAL: u64 = 50_000;

// Thread-safe Xieve flag
static SIEVE_ENABLED: AtomicBool = AtomicBool::new(true);

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║     RUSTYWALLET PUZZLE SOLVER v4.0 - XIEVE ENABLED              ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");
    
    // Parse command line args
    let args: Vec<String> = env::args().collect();
    let mut puzzle_num: u32 = 0;
    let mut xieve_enabled = DEFAULT_SIEVE_ENABLED;
    
    // Check for --no-xieve flag
    for arg in &args[1..] {
        if arg == "--no-xieve" || arg == "-n" {
            xieve_enabled = false;
        } else if let Ok(num) = arg.parse::<u32>() {
            puzzle_num = num;
        }
    }
    
    SIEVE_ENABLED.store(xieve_enabled, Ordering::Relaxed);
    
    // Get puzzle number if not provided
    if puzzle_num == 0 {
        print!("Enter puzzle number (57-100): ");
        let _ = stdout().flush();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        puzzle_num = input.trim().parse().unwrap_or(0);
    }
    
    if puzzle_num < 57 || puzzle_num > 100 {
        println!("[ERROR] Invalid puzzle number. Must be 57-100.");
        println!("\nAvailable puzzles:");
        for (bit, addr) in PUZZLES.iter() {
            println!("  #{}: {}", bit, addr);
        }
        return;
    }
    
    // Find puzzle in database
    let (target_addr, target_h160) = match PUZZLES.iter().find(|(b, _)| *b == puzzle_num) {
        Some((_, addr)) => {
            let h160_bytes = decode_address(addr).expect("Invalid puzzle address in database");
            (*addr, h160_bytes)
        }
        None => {
            println!("[ERROR] Puzzle #{} not found in database.", puzzle_num);
            return;
        }
    };
    
    // Calculate range
    let (range_start, range_end) = get_puzzle_range(puzzle_num);
    
    let threads = num_cpus::get_physical().max(2);
    
    println!("[PUZZLE] #{}", puzzle_num);
    println!("[TARGET] {}", target_addr);
    println!("[HASH160] {}", hex::encode(&target_h160));
    println!("[RANGE] 2^{} to 2^{}-1", puzzle_num - 1, puzzle_num);
    println!("[THREADS] {}", threads);
    if xieve_enabled {
        println!("[XIEVE] ENABLED - Modulus: {}, Remainder: {}", SIEVE_MODULUS, SIEVE_REMAINDER);
        println!("[XIEVE] Checking only {:.2}% of keys (skipping {:.2}%)", 
            100.0 / SIEVE_MODULUS as f64,
            100.0 - (100.0 / SIEVE_MODULUS as f64));
    } else {
        println!("[XIEVE] DISABLED (checking all keys)");
    }
    println!();
    println!("Usage: puzzle-demo <puzzle_num> [--no-xieve|-n]");
    println!("----------------------------------------------------------------------");
    
    let target_h160 = Arc::new(target_h160);
    let att = Arc::new(AtomicU64::new(0));
    let run = Arc::new(AtomicBool::new(true));
    let found = Arc::new(AtomicBool::new(false));
    
    let t0 = Instant::now();
    let mut handles = vec![];
    
    // Divide range among threads
    let range_size = range_end - range_start;
    let chunk_size = range_size / threads as u128;
    
    for i in 0..threads {
        let thread_start = range_start + (i as u128 * chunk_size);
        let thread_end = if i == threads - 1 { range_end } else { thread_start + chunk_size };
        
        let target = Arc::clone(&target_h160);
        let att_c = Arc::clone(&att);
        let run_c = Arc::clone(&run);
        let found_c = Arc::clone(&found);
        let addr = target_addr.to_string();
        
        handles.push(thread::spawn(move || {
            worker_optimized(i, thread_start, thread_end, target, att_c, run_c, found_c, &addr);
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
            let progress = (cur as f64 / range_size as f64) * 100.0;
            print!("\r[SCAN] {} | {}/s | {:.6}% | {}s   ",
                fmt(cur), fmt(spd), progress, t0.elapsed().as_secs());
            let _ = stdout().flush();
        }
    });
    
    // Ctrl+C handler
    let run_h = Arc::clone(&run);
    ctrlc::set_handler(move || {
        println!("\n[!] Stopping...");
        run_h.store(false, Ordering::Relaxed);
    }).ok();
    
    for h in handles { h.join().ok(); }
    
    let total = att.load(Ordering::Relaxed);
    let elapsed = t0.elapsed().as_secs_f64();
    
    println!("\n\n======================================================================");
    if found.load(Ordering::Relaxed) {
        println!("  🎉 PRIVATE KEY FOUND! Check puzzle_found.txt");
    } else {
        println!("  {} keys checked @ {}/s in {:.1}s", fmt(total), fmt((total as f64/elapsed) as u64), elapsed);
    }
    println!("======================================================================");
}

#[inline(never)]
fn worker_optimized(id: usize, start: u128, end: u128, target: Arc<[u8; 20]>,
                    att: Arc<AtomicU64>, run: Arc<AtomicBool>, found: Arc<AtomicBool>, addr: &str) {
    let g = ProjectivePoint::GENERATOR;
    let mut h160 = [0u8; 20];
    let mut la = 0u64;
    let mut checked = 0u64;
    
    let sieve_enabled = SIEVE_ENABLED.load(Ordering::Relaxed);
    
    // Xieve: Calculate starting point aligned to sieve
    let mut current_key = start;
    if sieve_enabled && SIEVE_MODULUS > 1 {
        // Align to next key that matches sieve pattern
        let remainder = (current_key % SIEVE_MODULUS as u128) as u64;
        if remainder != SIEVE_REMAINDER {
            let skip = if SIEVE_REMAINDER >= remainder {
                SIEVE_REMAINDER - remainder
            } else {
                SIEVE_MODULUS - remainder + SIEVE_REMAINDER
            };
            current_key += skip as u128;
        }
    }
    
    // Convert start to scalar
    let start_bytes = u128_to_bytes32(current_key);
    let scalar: Scalar = match Scalar::from_repr(start_bytes.into()).into_option() {
        Some(s) => s,
        None => return,
    };
    
    // Initial point = G * start
    let mut point: ProjectivePoint = g * scalar;
    
    // Pre-compute jump for Xieve (G * SIEVE_MODULUS)
    let jump_scalar = if sieve_enabled && SIEVE_MODULUS > 1 {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&SIEVE_MODULUS.to_be_bytes());
        Scalar::from_repr(bytes.into()).into_option()
    } else {
        None
    };
    let jump_point = jump_scalar.map(|s| g * s);
    
    while current_key < end && run.load(Ordering::Relaxed) && !found.load(Ordering::Relaxed) {
        for _ in 0..BATCH_SIZE {
            if current_key >= end { break; }
            
            // Get compressed public key directly from bytes
            let pk_bytes = point.to_bytes();
            
            if pk_bytes.len() == 33 {
                // Inline Hash160
                let sha = Sha256::digest(&pk_bytes);
                let rip = Ripemd160::digest(&sha);
                h160.copy_from_slice(&rip);
                
                checked += 1;
                
                // Compare
                if h160 == *target {
                    found.store(true, Ordering::Relaxed);
                    run.store(false, Ordering::Relaxed);
                    
                    let sk_bytes = u128_to_bytes32(current_key);
                    let sk_hex = hex::encode(&sk_bytes).trim_start_matches('0').to_string();
                    let wif = to_wif(&sk_bytes);
                    
                    println!("\n");
                    println!("╔══════════════════════════════════════════════════════════════════╗");
                    println!("║  🎉🎉🎉 PRIVATE KEY FOUND! 🎉🎉🎉                                ║");
                    println!("╠══════════════════════════════════════════════════════════════════╣");
                    println!("║ Thread: {}", id);
                    println!("║ Address: {}", addr);
                    println!("║ Private Key (HEX): {}", sk_hex);
                    println!("║ Private Key (WIF): {}", wif);
                    println!("║ Keys Checked: {}", checked);
                    println!("╚══════════════════════════════════════════════════════════════════╝");
                    
                    // Save to file
                    use std::fs::OpenOptions;
                    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("puzzle_found.txt") {
                        writeln!(f, "Puzzle Address: {}", addr).ok();
                        writeln!(f, "Private Key (HEX): {}", sk_hex).ok();
                        writeln!(f, "Private Key (WIF): {}", wif).ok();
                        writeln!(f, "").ok();
                    }
                    return;
                }
            }
            
            la += 1;
            
            // Xieve: Jump by SIEVE_MODULUS instead of 1
            if sieve_enabled && SIEVE_MODULUS > 1 {
                if let Some(jp) = jump_point {
                    current_key += SIEVE_MODULUS as u128;
                    point = point + jp;
                }
            } else {
                current_key += 1;
                point = point + g;
            }
            
            if la % UPDATE_INTERVAL == 0 {
                att.fetch_add(la, Ordering::Relaxed);
                la = 0;
                if !run.load(Ordering::Relaxed) { return; }
            }
        }
    }
    att.fetch_add(la, Ordering::Relaxed);
}

fn get_puzzle_range(puzzle_num: u32) -> (u128, u128) {
    let start: u128 = 1u128 << (puzzle_num - 1);
    let end: u128 = (1u128 << puzzle_num) - 1;
    (start, end)
}

fn u128_to_bytes32(val: u128) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[16..32].copy_from_slice(&val.to_be_bytes());
    bytes
}

fn decode_address(addr: &str) -> Option<[u8; 20]> {
    if !addr.starts_with('1') { return None; }
    let decoded = bs58::decode(addr).into_vec().ok()?;
    if decoded.len() != 25 { return None; }
    let mut h160 = [0u8; 20];
    h160.copy_from_slice(&decoded[1..21]);
    Some(h160)
}

fn to_wif(sk: &[u8; 32]) -> String {
    let mut extended = vec![0x80];
    extended.extend_from_slice(sk);
    extended.push(0x01);
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
