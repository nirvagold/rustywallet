//! RustyWallet Bech32 Demo v4.0 - HYPER OPTIMIZED
//! P2WPKH (bc1q) and P2TR (bc1p) with maximum CPU utilization

use rustywallet_bloom::BloomFilter;
use rustywallet_checker::{check_btc_balance, BitcoinBalance};
use rustywallet_keys::private_key::PrivateKey;
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use std::fs::{File, OpenOptions};
use std::io::{stdout, BufRead, BufReader, Write};
use std::sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc};
use std::thread;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use crossbeam_channel::{bounded, Sender, Receiver};
use rand::RngCore;
use k256::{ProjectivePoint, Scalar, AffinePoint};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;

// Hyper-tuned constants
const BATCH_SIZE: usize = 50_000;
const UPDATE_INTERVAL: usize = 10_000;
const BLOOM_FPR: f64 = 0.0000000001;

#[derive(Clone, Copy)]
struct Types { wpkh: bool, tr: bool }
struct Match { pk: [u8; 32], t: &'static str, a: String }

// Pre-computed bech32 charset as lookup table
const BECH32_CHARSET: [char; 32] = [
    'q','p','z','r','y','9','x','8','g','f','2','t','v','d','w','0',
    's','3','j','n','5','4','k','h','c','e','6','m','u','a','7','l'
];

fn main() {
    // Use physical cores only (no hyperthreading)
    let threads = num_cpus::get_physical().max(2);
    println!("\n======================================================================");
    println!("     RUSTYWALLET BECH32 v4.0 - HYPER OPTIMIZED");
    println!("======================================================================\n");
    
    print!("[1/3] Analyzing... ");
    let _ = stdout().flush();
    let (count, types) = analyze("addresses.txt");
    if count == 0 { println!("No bech32!"); return; }
    println!("{} bech32 addresses", fmt(count as u64));
    
    print!("[2/3] Loading bloom... ");
    let _ = stdout().flush();
    let t = Instant::now();
    let mut bloom = BloomFilter::new(count, BLOOM_FPR);
    let loaded = load("addresses.txt", &mut bloom);
    println!("{} in {:.1}s (~{}MB)", fmt(loaded), t.elapsed().as_secs_f64(), bloom.memory_usage()/1_000_000);
    
    let bloom = Arc::new(bloom);
    let (tx, rx): (Sender<Match>, Receiver<Match>) = bounded(8192);
    let att = Arc::new(AtomicU64::new(0));
    let mat = Arc::new(AtomicU64::new(0));
    let chk = Arc::new(AtomicU64::new(0));
    let bal = Arc::new(AtomicU64::new(0));
    let run = Arc::new(AtomicBool::new(true));
    
    println!("[3/3] {} threads | {}K batch | AVX2+BMI2", threads, BATCH_SIZE/1_000);
    println!("----------------------------------------------------------------------");
    
    let t0 = Instant::now();
    let mut hs = vec![];
    for _ in 0..threads {
        let b = Arc::clone(&bloom);
        let a = Arc::clone(&att);
        let m = Arc::clone(&mat);
        let t = tx.clone();
        let r = Arc::clone(&run);
        hs.push(thread::spawn(move || worker_hyper(b, a, m, t, r, types)));
    }
    drop(tx);
    
    let c = Arc::clone(&chk);
    let f = Arc::clone(&bal);
    let r = Arc::clone(&run);
    let checker = thread::spawn(move || balance_checker(rx, c, f, r));
    
    let a = Arc::clone(&att);
    let m = Arc::clone(&mat);
    let c = Arc::clone(&chk);
    let r = Arc::clone(&run);
    thread::spawn(move || {
        let mut last = 0u64;
        loop {
            thread::sleep(Duration::from_secs(2));
            if !r.load(Ordering::Relaxed) { break; }
            let cur = a.load(Ordering::Relaxed);
            let spd = cur.saturating_sub(last) / 2;
            last = cur;
            print!("\r{} | {}/s | B:{} C:{} | {}s   ",
                fmt(cur), fmt(spd), m.load(Ordering::Relaxed),
                c.load(Ordering::Relaxed), t0.elapsed().as_secs());
            let _ = stdout().flush();
        }
    });
    
    let rh = Arc::clone(&run);
    ctrlc::set_handler(move || { println!("\n[!] Stop"); rh.store(false, Ordering::Relaxed); }).ok();
    
    for h in hs { h.join().ok(); }
    run.store(false, Ordering::Relaxed);
    checker.join().ok();
    
    let total = att.load(Ordering::Relaxed);
    let elapsed = t0.elapsed().as_secs_f64();
    println!("\n\n======================================================================");
    println!("  {} keys @ {}/s | bloom:{} checked:{} balance:{}",
        fmt(total), fmt((total as f64/elapsed) as u64),
        mat.load(Ordering::Relaxed), chk.load(Ordering::Relaxed), bal.load(Ordering::Relaxed));
    println!("======================================================================");
}

fn analyze(f: &str) -> (usize, Types) {
    let file = match File::open(f) { Ok(f) => f, Err(_) => return (0, Types{wpkh:false,tr:false}) };
    let mut t = Types{wpkh:false,tr:false};
    let mut c = 0;
    for l in BufReader::with_capacity(4<<20, file).lines().flatten() {
        let a = l.trim();
        if a.starts_with("bc1q") { c += 1; t.wpkh = true; }
        else if a.starts_with("bc1p") { c += 1; t.tr = true; }
    }
    (c, t)
}

fn load(f: &str, b: &mut BloomFilter) -> u64 {
    let file = match File::open(f) { Ok(f) => f, Err(_) => return 0 };
    let mut c = 0u64;
    for l in BufReader::with_capacity(8<<20, file).lines().flatten() {
        let a = l.trim();
        if a.starts_with("bc1q") || a.starts_with("bc1p") {
            b.insert(a.to_lowercase().as_bytes());
            c += 1;
        }
    }
    c
}

#[inline(never)]
fn worker_hyper(bloom: Arc<BloomFilter>, att: Arc<AtomicU64>, mat: Arc<AtomicU64>,
                tx: Sender<Match>, run: Arc<AtomicBool>, types: Types) {
    // Stack-allocated buffers for zero heap allocation in hot path
    let mut pk33 = [0u8; 33];
    let mut h160 = [0u8; 20];
    let mut sha_out = [0u8; 32];
    let mut addr_bytes = [0u8; 64];
    let mut la = 0u64;
    let mut lm = 0u64;
    let mut rng = rand::thread_rng();
    let g = ProjectivePoint::GENERATOR;
    
    while run.load(Ordering::Relaxed) {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        
        let mut scalar: Scalar = match Scalar::from_repr(sk.into()).into_option() {
            Some(s) => s,
            None => continue,
        };
        let mut point: ProjectivePoint = g * scalar;
        
        for i in 0..BATCH_SIZE {
            // Inline affine conversion
            let affine: AffinePoint = point.into();
            let enc = affine.to_encoded_point(true);
            let bytes = enc.as_bytes();
            
            if bytes.len() == 33 {
                pk33.copy_from_slice(bytes);
                let cur_sk: [u8; 32] = scalar.to_repr().into();
                
                // P2WPKH - inline hash160
                if types.wpkh {
                    // SHA256
                    let sha_result = Sha256::digest(&pk33);
                    sha_out.copy_from_slice(&sha_result);
                    
                    // RIPEMD160
                    let rip_result = Ripemd160::digest(&sha_out);
                    h160.copy_from_slice(&rip_result);
                    
                    // Inline bech32 encode
                    let len = encode_bech32_inline(&mut addr_bytes, 0, &h160);
                    if bloom.contains(&addr_bytes[..len]) {
                        lm += 1;
                        let addr = String::from_utf8_lossy(&addr_bytes[..len]).to_string();
                        let _ = tx.try_send(Match { pk: cur_sk, t: "P2WPKH", a: addr });
                    }
                }
                
                // P2TR - x-only pubkey (skip hash160)
                if types.tr {
                    let len = encode_bech32m_inline(&mut addr_bytes, 1, &pk33[1..33]);
                    if bloom.contains(&addr_bytes[..len]) {
                        lm += 1;
                        let addr = String::from_utf8_lossy(&addr_bytes[..len]).to_string();
                        let _ = tx.try_send(Match { pk: cur_sk, t: "P2TR", a: addr });
                    }
                }
            }
            
            la += 1;
            point = point + g;
            scalar = scalar + Scalar::ONE;
            
            // Periodic update
            if i % UPDATE_INTERVAL == 0 && i > 0 {
                if !run.load(Ordering::Relaxed) { break; }
                att.fetch_add(la, Ordering::Relaxed);
                mat.fetch_add(lm, Ordering::Relaxed);
                la = 0; lm = 0;
            }
        }
        att.fetch_add(la, Ordering::Relaxed);
        mat.fetch_add(lm, Ordering::Relaxed);
        la = 0; lm = 0;
    }
}

// Zero-allocation bech32 encoding directly to byte buffer
#[inline(always)]
fn encode_bech32_inline(out: &mut [u8; 64], ver: u8, data: &[u8]) -> usize {
    out[0] = b'b'; out[1] = b'c'; out[2] = b'1';
    let mut pos = 3;
    
    let mut v = [0u8; 65];
    let mut n = 0;
    v[n] = ver; n += 1;
    
    let (mut acc, mut bits) = (0u32, 0u32);
    for &x in data {
        acc = (acc << 8) | x as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            v[n] = ((acc >> bits) & 31) as u8;
            n += 1;
        }
    }
    if bits > 0 {
        v[n] = ((acc << (5 - bits)) & 31) as u8;
        n += 1;
    }
    
    let cs = checksum_inline(&v[..n], 1);
    
    for i in 0..n {
        out[pos] = BECH32_CHARSET[v[i] as usize] as u8;
        pos += 1;
    }
    for c in cs {
        out[pos] = BECH32_CHARSET[c as usize] as u8;
        pos += 1;
    }
    pos
}

#[inline(always)]
fn encode_bech32m_inline(out: &mut [u8; 64], ver: u8, data: &[u8]) -> usize {
    out[0] = b'b'; out[1] = b'c'; out[2] = b'1';
    let mut pos = 3;
    
    let mut v = [0u8; 65];
    let mut n = 0;
    v[n] = ver; n += 1;
    
    let (mut acc, mut bits) = (0u32, 0u32);
    for &x in data {
        acc = (acc << 8) | x as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            v[n] = ((acc >> bits) & 31) as u8;
            n += 1;
        }
    }
    if bits > 0 {
        v[n] = ((acc << (5 - bits)) & 31) as u8;
        n += 1;
    }
    
    let cs = checksum_inline(&v[..n], 0x2bc830a3);
    
    for i in 0..n {
        out[pos] = BECH32_CHARSET[v[i] as usize] as u8;
        pos += 1;
    }
    for c in cs {
        out[pos] = BECH32_CHARSET[c as usize] as u8;
        pos += 1;
    }
    pos
}

#[inline(always)]
fn checksum_inline(data: &[u8], k: u32) -> [u8; 6] {
    let mut c = 1u32;
    // hrp expansion for "bc"
    c = polymod(c) ^ 3; // 'b' >> 5
    c = polymod(c) ^ 3; // 'c' >> 5
    c = polymod(c);
    c = polymod(c) ^ 2; // 'b' & 31
    c = polymod(c) ^ 3; // 'c' & 31
    
    for &v in data { c = polymod(c) ^ v as u32; }
    for _ in 0..6 { c = polymod(c); }
    c ^= k;
    
    [((c>>25)&31) as u8, ((c>>20)&31) as u8, ((c>>15)&31) as u8, 
     ((c>>10)&31) as u8, ((c>>5)&31) as u8, (c&31) as u8]
}

#[inline(always)]
fn polymod(pre: u32) -> u32 {
    let b = pre >> 25;
    let mut r = (pre & 0x1ffffff) << 5;
    if b & 1 != 0 { r ^= 0x3b6a57b2; }
    if b & 2 != 0 { r ^= 0x26508e6d; }
    if b & 4 != 0 { r ^= 0x1ea119fa; }
    if b & 8 != 0 { r ^= 0x3d4233dd; }
    if b & 16 != 0 { r ^= 0x2a1462b3; }
    r
}

fn balance_checker(rx: Receiver<Match>, chk: Arc<AtomicU64>, bal: Arc<AtomicU64>, run: Arc<AtomicBool>) {
    let rt = Runtime::new().unwrap();
    while run.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(m) => {
                chk.fetch_add(1, Ordering::Relaxed);
                let addr = m.a.clone();
                let res = rt.block_on(async { check_btc_balance(&addr).await });
                match res {
                    Ok(b) => {
                        save_found(&m, &b);
                        println!("\n[🔍] {} | {} sat", addr, fmt(b.balance));
                        if b.balance > 0 || b.unconfirmed != 0 {
                            bal.fetch_add(1, Ordering::Relaxed);
                            println!("[💰] BALANCE! {} | {} sat", addr, fmt(b.balance));
                            save_balance(&m, &b);
                        }
                    }
                    Err(e) => {
                        save_error(&m, &e.to_string());
                        println!("\n[⚠️] {}: {}", addr, e);
                    }
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => continue,
        }
    }
    for m in rx.try_iter() {
        let res = rt.block_on(async { check_btc_balance(&m.a).await });
        if let Ok(b) = res { save_found(&m, &b); }
    }
}

fn save_found(m: &Match, b: &BitcoinBalance) {
    let pk = PrivateKey::from_bytes(m.pk).unwrap();
    let wif = pk.to_wif(rustywallet_keys::prelude::Network::Mainnet);
    let hex = hex::encode(&m.pk);
    let pub_hex = hex::encode(pk.public_key().to_compressed());
    
    let mut f = OpenOptions::new().create(true).append(true).open("found_bech32.txt").unwrap();
    writeln!(f, "========================================").ok();
    writeln!(f, "{} | {} | {} sat", m.t, m.a, b.balance).ok();
    writeln!(f, "HEX: {} | WIF: {}", hex, wif).ok();
    writeln!(f, "PUB: {} | TX: {}", pub_hex, b.tx_count).ok();
    writeln!(f, "========================================\n").ok();
}

fn save_balance(m: &Match, b: &BitcoinBalance) {
    let pk = PrivateKey::from_bytes(m.pk).unwrap();
    let wif = pk.to_wif(rustywallet_keys::prelude::Network::Mainnet);
    let hex = hex::encode(&m.pk);
    
    let mut f = OpenOptions::new().create(true).append(true).open("found_bech32_balance.txt").unwrap();
    writeln!(f, "💰 {} | {} | {} sat | {} | {}", m.t, m.a, b.balance, hex, wif).ok();
}

fn save_error(m: &Match, e: &str) {
    let hex = hex::encode(&m.pk);
    let mut f = OpenOptions::new().create(true).append(true).open("found_bech32.txt").unwrap();
    writeln!(f, "{} | {} | ERROR: {} | HEX: {}", m.t, m.a, e, hex).ok();
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
