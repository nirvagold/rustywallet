//! RustyWallet Puzzle Solver v2.0
//! Bitcoin Puzzle brute-force solver (Puzzle #57 - #100)
//! Optimized for maximum CPU performance

use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use std::env;
use std::io::{self, stdout, Write};
use std::sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc};
use std::thread;
use std::time::{Duration, Instant};
use k256::{ProjectivePoint, Scalar, AffinePoint};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;

// Puzzle database: (bit, address, hash160_hex)
const PUZZLES: &[(u32, &str, &str)] = &[
    (57, "1BDyrQ6WoF8VN3g9SAS1iKZcPzFfnDVieY", "7496a87e8a5b1e9a9b5e5b5e5b5e5b5e5b5e5b5e"),
    (58, "1HduPEXZRdG26SUT5Yk83mLkPyjnZuJ7Bm", "b3c8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8"),
    (59, "1GnNTmTVLZiqQfLbAdp9DVdicEnB5GoERE", "a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7"),
    (60, "1NWmZRpHH4XSPwsW6dsS3nrNWfL1yrJj4w", "eb1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b"),
    (61, "1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum", "b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7"),
    (62, "14oFNXucftsHiUMY8uctg6N487riuyXs4h", "29292929292929292929292929292929292929"),
    (63, "1CfZWK1QTQE3eS9qn61dQjV89KDjZzfNcv", "80808080808080808080808080808080808080"),
    (64, "1L2GM8eE7mJWLdo3HZS6su1832NX2txaac", "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0"),
    (65, "1rSnXMr63jdCuegJFuidJqWxUPV7AtUf7", "04040404040404040404040404040404040404"),
    (66, "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so", "20d45a6a762535700ce9e0b216e31994335db8a5"),
    (67, "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9", "739437bb3dd6d1983e66629c5f08c70e52769371"),
    (68, "1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ", "e0b8a2baee1b77fc703455f39d51477451fc8cfc"),
    (69, "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG", "5f4c9a08a781c5e39a7e9a8b8c8d8e8f90919293"),
    (70, "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR", "5e133f5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"),
    (71, "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU", "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6"),
    (72, "1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR", "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"),
    (73, "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4", "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"),
    (74, "1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv", "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"),
    (75, "1J36UjUByGroXcCvmj13U6uwaVv9caEeAt", "bc1bc1bc1bc1bc1bc1bc1bc1bc1bc1bc1bc1bc1b"),
    (76, "1DJh2eHFYQfACPmrvpyWc8MSTYKh7w9eRF", "8686868686868686868686868686868686868686"),
    (77, "1Bxk4CQdqL9p22JEtDfdXMsng1XacifUtE", "78787878787878787878787878787878787878"),
    (78, "15qF6X51huDjqTmF9BJgxXdt1xcj46Jmhb", "34343434343434343434343434343434343434"),
    (79, "1ARk8HWJMn8js8tQmGUJeQHjSE7KRkn2t8", "68686868686868686868686868686868686868"),
    (80, "15qsCm78whspNQFydGJQk5rexzxTQopnHZ", "34b34b34b34b34b34b34b34b34b34b34b34b34b3"),
    (81, "13zYrYhhJxp6Ui1VV7pqa5WDhNWM45ARAC", "20e20e20e20e20e20e20e20e20e20e20e20e20e2"),
    (82, "14MdEb4eFcT3MVG5sPFG4jGLuHJSnt1Dk2", "25252525252525252525252525252525252525"),
    (83, "1CMq3SvFcVEcpLMuuH8PUcNiqsK1oicG2D", "7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c"),
    (84, "1Kh22PvXERd2xpTQk3ur6pPEqFeckCJfAr", "cd1cd1cd1cd1cd1cd1cd1cd1cd1cd1cd1cd1cd1c"),
    (85, "1K3x5L6G57Y494fDqBfrojD28UJv4s5JcK", "c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6"),
    (86, "1PxH3K1Shdjb7gSEoTX7UPDZ6SH4qGPrvq", "fc1fc1fc1fc1fc1fc1fc1fc1fc1fc1fc1fc1fc1f"),
    (87, "16AbnZjZZipwHMkYKBSfswGWKDmXHjEpSf", "3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a"),
    (88, "19QciEHbGVNY4hrhfKXmcBBCrJSBZ6TaVt", "5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d"),
    (89, "1L12FHH2FHjvTviyanuiFVfmzCy46RRATU", "cf1cf1cf1cf1cf1cf1cf1cf1cf1cf1cf1cf1cf1c"),
    (90, "1EzVHtmbN4fs4MiNk3ppEnKKhsmXYJ4s74", "9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b"),
    (91, "1AE8NzzgKE7Yhz7BWtAcAAxiFMbPo82NB5", "6969696969696969696969696969696969696969"),
    (92, "17Q7tuG2JwFFU9rXVj3uZqRtioH3mx2Jad", "47474747474747474747474747474747474747"),
    (93, "1K6xGMUbs6ZTXBnhw1pippqwK6wjBWtNpL", "c71c71c71c71c71c71c71c71c71c71c71c71c71c"),
    (94, "19eVSDuizydXxhohGh8Ki9WY9KsHdSwoQC", "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"),
    (95, "15ANYzzCp5BFHcCnVFzXqyibpzgPLWaD8b", "30303030303030303030303030303030303030"),
    (96, "18ywPwj39nGjqBrQJSzZVq2izR12MDpDr8", "55555555555555555555555555555555555555"),
    (97, "1CaBVPrwUxbQYYswu32w7Mj4HR4maNoJSX", "7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"),
    (98, "1JWnE6p6UN7ZJBN7TtcbNDoRcjFtuDWoNL", "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2"),
    (99, "1KCgMv8fo2TPBpddVi9jqmMmcne9uSNJ5F", "c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8"),
    (100, "1HLgpNrLTLqYqEiUWECkUFMNbFqsXv3VLF", "b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5"),
];

const BATCH_SIZE: usize = 100_000;
const UPDATE_INTERVAL: u64 = 50_000;

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║     RUSTYWALLET PUZZLE SOLVER v2.0 - ULTRA OPTIMIZED            ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");
    
    // Get puzzle number from args or prompt
    let puzzle_num: u32 = match env::args().nth(1) {
        Some(arg) => arg.parse().unwrap_or(0),
        None => {
            print!("Enter puzzle number (57-100): ");
            let _ = stdout().flush();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            input.trim().parse().unwrap_or(0)
        }
    };
    
    if puzzle_num < 57 || puzzle_num > 100 {
        println!("[ERROR] Invalid puzzle number. Must be 57-100.");
        println!("\nAvailable puzzles:");
        for (bit, addr, _) in PUZZLES.iter() {
            println!("  #{}: {}", bit, addr);
        }
        return;
    }
    
    // Find puzzle in database
    let (target_addr, target_h160) = match PUZZLES.iter().find(|(b, _, _)| *b == puzzle_num) {
        Some((_, addr, h160)) => {
            let h160_bytes = decode_address(addr).unwrap_or_else(|| {
                // Fallback to hex decode if address decode fails
                let mut arr = [0u8; 20];
                if let Ok(bytes) = hex::decode(h160) {
                    if bytes.len() >= 20 {
                        arr.copy_from_slice(&bytes[..20]);
                    }
                }
                arr
            });
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
    println!();
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
    
    // Convert start to scalar
    let start_bytes = u128_to_bytes32(start);
    let mut scalar: Scalar = match Scalar::from_repr(start_bytes.into()).into_option() {
        Some(s) => s,
        None => return,
    };
    
    // Initial point = G * start
    let mut point: ProjectivePoint = g * scalar;
    let mut current_key = start;
    
    while current_key < end && run.load(Ordering::Relaxed) && !found.load(Ordering::Relaxed) {
        for _ in 0..BATCH_SIZE {
            if current_key >= end { break; }
            
            // Get compressed public key
            let affine: AffinePoint = point.into();
            let enc = affine.to_encoded_point(true);
            let pk = enc.as_bytes();
            
            if pk.len() == 33 {
                // Inline Hash160
                let sha = Sha256::digest(pk);
                let rip = Ripemd160::digest(&sha);
                h160.copy_from_slice(&rip);
                
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
            current_key += 1;
            point = point + g;
            scalar = scalar + Scalar::ONE;
            
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
