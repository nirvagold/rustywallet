//! RustyWallet Checker Demo v11.0 - DUAL BLOOM (Hash160 + Address)
//! 
//! Strategy: Hash160 pre-filter + Address string verification
//! - Hash160 bloom: fast pre-filter (may have false positives)
//! - Address bloom: accurate verification (no false positives)

use rustywallet_bloom::BloomFilter;
use rustywallet_checker::{check_btc_balance, BitcoinBalance};
use rustywallet_keys::private_key::PrivateKey;
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use std::collections::HashSet;
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

const BATCH_SIZE: usize = 256;
const BATCHES_PER_ROUND: usize = 400;
const BALANCE_CHECK_RATE: u64 = 10;
const BLOOM_FPR: f64 = 0.0000001;
const UPDATE_INTERVAL: usize = 25_600;

#[derive(Clone, Copy)]
struct AddrTypes { p2pkh: bool, p2sh: bool, p2wpkh: bool, p2tr: bool }
struct Match { pk: [u8; 32], t: &'static str, a: String }

fn main() {
    let threads = num_cpus::get_physical().max(2);
    println!("\n======================================================================");
    println!("   RUSTYWALLET CHECKER v11.0 - DUAL BLOOM (Hash160 + Address)");
    println!("======================================================================\n");
    
    print!("[1/5] Analyzing... ");
    let _ = stdout().flush();
    let (count, types) = analyze("addresses.txt");
    if count == 0 { println!("No addresses!"); return; }
    println!("{} addresses", fmt(count as u64));
    
    // Build Hash160 bloom for pre-filtering
    print!("[2/5] Building Hash160 bloom (pre-filter)... ");
    let _ = stdout().flush();
    let start = Instant::now();
    let mut bloom_h160 = BloomFilter::new(count * 2, 0.001); // Higher FPR OK for pre-filter
    let h160_count = load_hash160("addresses.txt", &mut bloom_h160);
    println!("{} in {:.1}s", fmt(h160_count), start.elapsed().as_secs_f64());
    
    // Build Address bloom for verification
    print!("[3/5] Building Address bloom (verification)... ");
    let _ = stdout().flush();
    let start = Instant::now();
    let mut bloom_addr = BloomFilter::new(count, BLOOM_FPR);
    let addr_count = load_addresses("addresses.txt", &mut bloom_addr);
    let mem = (bloom_h160.memory_usage() + bloom_addr.memory_usage()) / 1_000_000;
    println!("{} in {:.1}s (~{}MB total)", fmt(addr_count), start.elapsed().as_secs_f64(), mem);
    
    let bloom_h160 = Arc::new(bloom_h160);
    let bloom_addr = Arc::new(bloom_addr);
    
    println!("[4/5] Validating...");
    validate_blooms(&bloom_h160, &bloom_addr);
    
    let (tx, rx): (Sender<Match>, Receiver<Match>) = bounded(512);
    let att = Arc::new(AtomicU64::new(0));
    let mat = Arc::new(AtomicU64::new(0));
    let pre = Arc::new(AtomicU64::new(0)); // Pre-filter matches
    let chk = Arc::new(AtomicU64::new(0));
    let bal = Arc::new(AtomicU64::new(0));
    let run = Arc::new(AtomicBool::new(true));

    
    println!("[5/5] {} threads | Dual Bloom | Batch Affine\n", threads);
    println!("----------------------------------------------------------------------");
    
    let t0 = Instant::now();
    let mut hs = vec![];
    for _ in 0..threads {
        let bh = Arc::clone(&bloom_h160);
        let ba = Arc::clone(&bloom_addr);
        let a = Arc::clone(&att);
        let m = Arc::clone(&mat);
        let p = Arc::clone(&pre);
        let t = tx.clone();
        let r = Arc::clone(&run);
        hs.push(thread::spawn(move || worker(bh, ba, a, m, p, t, r, types)));
    }
    drop(tx);
    
    let c = Arc::clone(&chk);
    let f = Arc::clone(&bal);
    let r = Arc::clone(&run);
    let checker = thread::spawn(move || balance_checker(rx, c, f, r));
    
    let a = Arc::clone(&att);
    let m = Arc::clone(&mat);
    let p = Arc::clone(&pre);
    let c = Arc::clone(&chk);
    let r = Arc::clone(&run);
    let reporter = thread::spawn(move || {
        let mut last = 0u64;
        loop {
            thread::sleep(Duration::from_secs(2));
            if !r.load(Ordering::Relaxed) { break; }
            let cur = a.load(Ordering::Relaxed);
            let pre_m = p.load(Ordering::Relaxed);
            let addr_m = m.load(Ordering::Relaxed);
            print!("\r{} | {}/s | Pre:{} Addr:{} API:{} | {}s   ", 
                fmt(cur), fmt((cur-last)/2), pre_m, addr_m, c.load(Ordering::Relaxed), t0.elapsed().as_secs());
            let _ = stdout().flush();
            last = cur;
        }
    });
    
    ctrlc::set_handler({ let r = Arc::clone(&run); move || { println!("\n[!] Stop"); r.store(false, Ordering::Relaxed); }}).ok();
    for h in hs { h.join().ok(); }
    run.store(false, Ordering::Relaxed);
    checker.join().ok();
    reporter.join().ok();
    
    let total = att.load(Ordering::Relaxed);
    let pre_m = pre.load(Ordering::Relaxed);
    let addr_m = mat.load(Ordering::Relaxed);
    println!("\n\n======================================================================");
    println!("  {} keys @ {}/s", fmt(total), fmt((total as f64/t0.elapsed().as_secs_f64()) as u64));
    println!("  Pre-filter: {} | Address match: {} | API: {} | Balance: {}", 
        pre_m, addr_m, chk.load(Ordering::Relaxed), bal.load(Ordering::Relaxed));
    println!("======================================================================");
}

fn analyze(f: &str) -> (usize, AddrTypes) {
    let file = match File::open(f) { Ok(f) => f, Err(_) => return (0, AddrTypes{p2pkh:false,p2sh:false,p2wpkh:false,p2tr:false}) };
    let mut t = AddrTypes{p2pkh:false,p2sh:false,p2wpkh:false,p2tr:false};
    let mut c = 0;
    for l in BufReader::with_capacity(4<<20, file).lines().flatten() {
        let a = l.trim();
        if a.is_empty() || a.starts_with('#') { continue; }
        // Validate address format
        if !is_valid_address(a) { continue; }
        c += 1;
        if !t.p2pkh && a.starts_with('1') { t.p2pkh = true; }
        if !t.p2sh && a.starts_with('3') { t.p2sh = true; }
        if !t.p2wpkh && a.starts_with("bc1q") { t.p2wpkh = true; }
        if !t.p2tr && a.starts_with("bc1p") { t.p2tr = true; }
    }
    (c, t)
}

fn is_valid_address(addr: &str) -> bool {
    let len = addr.len();
    if addr.starts_with('1') { len >= 26 && len <= 35 }
    else if addr.starts_with('3') { len >= 26 && len <= 35 }
    else if addr.starts_with("bc1q") { len >= 42 && len <= 62 }
    else if addr.starts_with("bc1p") { len >= 62 && len <= 62 }
    else { false }
}

fn load_hash160(f: &str, bloom: &mut BloomFilter) -> u64 {
    let file = match File::open(f) { Ok(f) => f, Err(_) => return 0 };
    let mut count = 0u64;
    for line in BufReader::with_capacity(8<<20, file).lines().flatten() {
        let addr = line.trim();
        if addr.is_empty() || addr.starts_with('#') || !is_valid_address(addr) { continue; }
        if let Some(h160) = decode_addr_to_hash160(addr) {
            bloom.insert(&h160);
            count += 1;
        }
    }
    count
}

fn load_addresses(f: &str, bloom: &mut BloomFilter) -> u64 {
    let file = match File::open(f) { Ok(f) => f, Err(_) => return 0 };
    let mut count = 0u64;
    for line in BufReader::with_capacity(8<<20, file).lines().flatten() {
        let addr = line.trim();
        if addr.is_empty() || addr.starts_with('#') || !is_valid_address(addr) { continue; }
        bloom.insert(addr.as_bytes());
        count += 1;
    }
    count
}


fn decode_addr_to_hash160(addr: &str) -> Option<[u8; 20]> {
    if addr.starts_with('1') || addr.starts_with('3') {
        let decoded = bs58::decode(addr).into_vec().ok()?;
        if decoded.len() != 25 { return None; }
        let mut h160 = [0u8; 20];
        h160.copy_from_slice(&decoded[1..21]);
        Some(h160)
    } else if addr.starts_with("bc1q") || addr.starts_with("bc1p") {
        bech32_decode_hash160(addr)
    } else { None }
}

fn bech32_decode_hash160(addr: &str) -> Option<[u8; 20]> {
    let addr_lower = addr.to_lowercase();
    let sep_pos = addr_lower.rfind('1')?;
    let data_part = &addr_lower[sep_pos + 1..];
    if data_part.len() < 7 { return None; }
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut values = Vec::with_capacity(data_part.len() - 6);
    for c in data_part[..data_part.len()-6].chars() {
        let idx = CHARSET.iter().position(|&x| x == c as u8)?;
        values.push(idx as u8);
    }
    if values.is_empty() { return None; }
    let mut result = Vec::new();
    let mut acc = 0u32; let mut bits = 0u32;
    for &v in &values[1..] {
        acc = (acc << 5) | v as u32; bits += 5;
        if bits >= 8 { bits -= 8; result.push((acc >> bits) as u8); }
    }
    if result.len() >= 20 {
        let mut h160 = [0u8; 20];
        h160.copy_from_slice(&result[..20]);
        Some(h160)
    } else { None }
}

fn validate_blooms(bloom_h160: &BloomFilter, bloom_addr: &BloomFilter) {
    // Test known address
    let test_addr = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    let test_h160 = decode_addr_to_hash160(test_addr).unwrap();
    
    // Generate hash160 from private key 1
    let test_sk: [u8; 32] = { let mut b = [0u8; 32]; b[31] = 1; b };
    let scalar: Scalar = Scalar::from_repr(test_sk.into()).unwrap();
    let point: ProjectivePoint = ProjectivePoint::GENERATOR * scalar;
    let affine: AffinePoint = point.into();
    let encoded = affine.to_encoded_point(true);
    let gen_h160 = hash160(encoded.as_bytes());
    
    println!("  Hash160 match: {}", if gen_h160 == test_h160 { "OK" } else { "FAIL" });
    
    // Test bloom filters with addresses from file
    let test_addrs = ["34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo", "1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF"];
    for addr in &test_addrs {
        let in_addr_bloom = bloom_addr.contains(addr.as_bytes());
        println!("  {} in addr bloom: {}", addr, if in_addr_bloom { "YES" } else { "NO" });
    }
}


/// Worker with dual bloom filter: hash160 pre-filter + address verification
fn worker(bloom_h160: Arc<BloomFilter>, bloom_addr: Arc<BloomFilter>,
          att: Arc<AtomicU64>, mat: Arc<AtomicU64>, pre: Arc<AtomicU64>,
          tx: Sender<Match>, run: Arc<AtomicBool>, types: AddrTypes) {
    let g = ProjectivePoint::GENERATOR;
    let mut rng = rand::thread_rng();
    let mut la = 0u64;
    let mut lm = 0u64;
    let mut lp = 0u64;
    
    while run.load(Ordering::Relaxed) {
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let mut scalar: Scalar = match Scalar::from_repr(sk_bytes.into()).into_option() {
            Some(s) => s, None => continue,
        };
        let mut point = g * scalar;
        
        for _ in 0..BATCHES_PER_ROUND {
            if !run.load(Ordering::Relaxed) { break; }
            
            for _ in 0..BATCH_SIZE {
                let affine: AffinePoint = point.into();
                let encoded = affine.to_encoded_point(true);
                let pubkey = encoded.as_bytes();
                
                if pubkey.len() == 33 {
                    let h160 = hash160(pubkey);
                    let sk: [u8; 32] = scalar.to_repr().into();
                    
                    // P2PKH: check hash160 pre-filter, then address bloom
                    if types.p2pkh && bloom_h160.contains(&h160) {
                        lp += 1;
                        let addr = encode_p2pkh(&h160);
                        if bloom_addr.contains(addr.as_bytes()) {
                            lm += 1;
                            let _ = tx.try_send(Match { pk: sk, t: "P2PKH", a: addr });
                        }
                    }
                    
                    // P2WPKH: same hash160
                    if types.p2wpkh && bloom_h160.contains(&h160) {
                        lp += 1;
                        let addr = encode_p2wpkh(&h160);
                        if bloom_addr.contains(addr.as_bytes()) {
                            lm += 1;
                            let _ = tx.try_send(Match { pk: sk, t: "P2WPKH", a: addr });
                        }
                    }
                    
                    // P2SH-P2WPKH: different hash (script hash)
                    if types.p2sh {
                        let sh = p2sh_script_hash(&h160);
                        if bloom_h160.contains(&sh) {
                            lp += 1;
                            let addr = encode_p2sh(&sh);
                            if bloom_addr.contains(addr.as_bytes()) {
                                lm += 1;
                                let _ = tx.try_send(Match { pk: sk, t: "P2SH", a: addr });
                            }
                        }
                    }
                    
                    // P2TR: x-only pubkey
                    if types.p2tr {
                        let xonly = &pubkey[1..33];
                        let mut h160_tr = [0u8; 20];
                        h160_tr.copy_from_slice(&xonly[..20]);
                        if bloom_h160.contains(&h160_tr) {
                            lp += 1;
                            let addr = encode_p2tr(xonly);
                            if bloom_addr.contains(addr.as_bytes()) {
                                lm += 1;
                                let _ = tx.try_send(Match { pk: sk, t: "P2TR", a: addr });
                            }
                        }
                    }
                }
                
                la += 1;
                point = point + g;
                scalar = scalar + Scalar::ONE;
            }
            
            if la >= UPDATE_INTERVAL as u64 {
                att.fetch_add(la, Ordering::Relaxed);
                mat.fetch_add(lm, Ordering::Relaxed);
                pre.fetch_add(lp, Ordering::Relaxed);
                la = 0; lm = 0; lp = 0;
            }
        }
        
        att.fetch_add(la, Ordering::Relaxed);
        mat.fetch_add(lm, Ordering::Relaxed);
        pre.fetch_add(lp, Ordering::Relaxed);
        la = 0; lm = 0; lp = 0;
    }
}

#[inline(always)]
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rip = Ripemd160::digest(&sha);
    let mut out = [0u8; 20]; out.copy_from_slice(&rip); out
}

#[inline(always)]
fn p2sh_script_hash(h160: &[u8; 20]) -> [u8; 20] {
    let mut script = [0u8; 22];
    script[0] = 0x00; script[1] = 0x14;
    script[2..22].copy_from_slice(h160);
    hash160(&script)
}

fn encode_p2pkh(h160: &[u8; 20]) -> String {
    let mut buf = [0u8; 25]; buf[0] = 0x00; buf[1..21].copy_from_slice(h160);
    let c = Sha256::digest(&Sha256::digest(&buf[..21]));
    buf[21..25].copy_from_slice(&c[..4]);
    bs58::encode(&buf).into_string()
}

fn encode_p2sh(h160: &[u8; 20]) -> String {
    let mut buf = [0u8; 25]; buf[0] = 0x05; buf[1..21].copy_from_slice(h160);
    let c = Sha256::digest(&Sha256::digest(&buf[..21]));
    buf[21..25].copy_from_slice(&c[..4]);
    bs58::encode(&buf).into_string()
}

fn encode_p2wpkh(h160: &[u8; 20]) -> String {
    let mut out = String::with_capacity(62);
    bech32_encode(&mut out, "bc", 0, h160); out
}

fn encode_p2tr(xonly: &[u8]) -> String {
    let mut out = String::with_capacity(62);
    bech32m_encode(&mut out, "bc", 1, xonly); out
}


fn bech32_encode(out: &mut String, hrp: &str, version: u8, data: &[u8]) {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    out.push_str(hrp); out.push('1');
    let mut values = [0u8; 65]; let mut idx = 0;
    values[idx] = version; idx += 1;
    let mut acc = 0u32; let mut bits = 0u32;
    for &b in data { acc = (acc << 8) | b as u32; bits += 8; while bits >= 5 { bits -= 5; values[idx] = ((acc >> bits) & 31) as u8; idx += 1; } }
    if bits > 0 { values[idx] = ((acc << (5 - bits)) & 31) as u8; idx += 1; }
    let checksum = bech32_checksum(hrp, &values[..idx], 1);
    for i in 0..idx { out.push(CHARSET[values[i] as usize] as char); }
    for c in checksum { out.push(CHARSET[c as usize] as char); }
}

fn bech32m_encode(out: &mut String, hrp: &str, version: u8, data: &[u8]) {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    out.push_str(hrp); out.push('1');
    let mut values = [0u8; 65]; let mut idx = 0;
    values[idx] = version; idx += 1;
    let mut acc = 0u32; let mut bits = 0u32;
    for &b in data { acc = (acc << 8) | b as u32; bits += 8; while bits >= 5 { bits -= 5; values[idx] = ((acc >> bits) & 31) as u8; idx += 1; } }
    if bits > 0 { values[idx] = ((acc << (5 - bits)) & 31) as u8; idx += 1; }
    let checksum = bech32_checksum(hrp, &values[..idx], 0x2bc830a3);
    for i in 0..idx { out.push(CHARSET[values[i] as usize] as char); }
    for c in checksum { out.push(CHARSET[c as usize] as char); }
}

fn bech32_checksum(hrp: &str, data: &[u8], constant: u32) -> [u8; 6] {
    let mut chk = 1u32;
    for c in hrp.bytes() { chk = bech32_polymod(chk) ^ (c >> 5) as u32; }
    chk = bech32_polymod(chk);
    for c in hrp.bytes() { chk = bech32_polymod(chk) ^ (c & 31) as u32; }
    for &v in data { chk = bech32_polymod(chk) ^ v as u32; }
    for _ in 0..6 { chk = bech32_polymod(chk); }
    chk ^= constant;
    [((chk >> 25) & 31) as u8, ((chk >> 20) & 31) as u8, ((chk >> 15) & 31) as u8, ((chk >> 10) & 31) as u8, ((chk >> 5) & 31) as u8, (chk & 31) as u8]
}

#[inline(always)]
fn bech32_polymod(pre: u32) -> u32 {
    let b = pre >> 25;
    ((pre & 0x1ffffff) << 5) ^ (if b & 1 != 0 { 0x3b6a57b2 } else { 0 }) ^ (if b & 2 != 0 { 0x26508e6d } else { 0 }) ^ (if b & 4 != 0 { 0x1ea119fa } else { 0 }) ^ (if b & 8 != 0 { 0x3d4233dd } else { 0 }) ^ (if b & 16 != 0 { 0x2a1462b3 } else { 0 })
}

fn balance_checker(rx: Receiver<Match>, chk: Arc<AtomicU64>, bal: Arc<AtomicU64>, run: Arc<AtomicBool>) {
    let rt = Runtime::new().unwrap();
    while run.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(m) => {
                chk.fetch_add(1, Ordering::Relaxed);
                let result = rt.block_on(async { check_btc_balance(&m.a).await });
                match result {
                    Ok(b) => {
                        save_match(&m, &b);
                        println!("\n[MATCH] {} | {} sat", m.a, fmt(b.balance));
                        if b.balance > 0 || b.unconfirmed != 0 {
                            bal.fetch_add(1, Ordering::Relaxed);
                            println!("[💰] BALANCE! {} | {} sat", m.a, fmt(b.balance));
                            save_balance(&m, &b);
                        }
                    }
                    Err(e) => { save_error(&m, &e.to_string()); println!("\n[ERR] {}: {}", m.a, e); }
                }
                thread::sleep(Duration::from_millis(1000 / BALANCE_CHECK_RATE));
            }
            Err(_) => continue,
        }
    }
    for m in rx.try_iter() {
        let result = rt.block_on(async { check_btc_balance(&m.a).await });
        if let Ok(b) = result { save_match(&m, &b); }
    }
}

fn save_match(m: &Match, b: &BitcoinBalance) {
    let pk = PrivateKey::from_bytes(m.pk).unwrap();
    let wif = pk.to_wif(rustywallet_keys::prelude::Network::Mainnet);
    let mut f = OpenOptions::new().create(true).append(true).open("found.txt").unwrap();
    writeln!(f, "=== {} ===\nAddress: {}\nBalance: {} sat\nHEX: {}\nWIF: {}\n", m.t, m.a, b.balance, hex::encode(&m.pk), wif).ok();
}

fn save_balance(m: &Match, b: &BitcoinBalance) {
    let pk = PrivateKey::from_bytes(m.pk).unwrap();
    let wif = pk.to_wif(rustywallet_keys::prelude::Network::Mainnet);
    let mut f = OpenOptions::new().create(true).append(true).open("found_with_balance.txt").unwrap();
    writeln!(f, "*** BALANCE ***\n{}: {}\nBalance: {} sat\nHEX: {}\nWIF: {}\n", m.t, m.a, b.balance, hex::encode(&m.pk), wif).ok();
}

fn save_error(m: &Match, err: &str) {
    let pk = PrivateKey::from_bytes(m.pk).unwrap();
    let wif = pk.to_wif(rustywallet_keys::prelude::Network::Mainnet);
    let mut f = OpenOptions::new().create(true).append(true).open("found.txt").unwrap();
    writeln!(f, "=== {} (ERR) ===\nAddress: {}\nError: {}\nHEX: {}\nWIF: {}\n", m.t, m.a, err, hex::encode(&m.pk), wif).ok();
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
