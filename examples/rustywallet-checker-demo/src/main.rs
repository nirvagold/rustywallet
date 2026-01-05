//! RustyWallet Checker Demo v9.0 - ULTRA OPTIMIZED
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

const BATCH_SIZE: usize = 100_000;
const BALANCE_CHECK_RATE: u64 = 10;
const BLOOM_FPR: f64 = 0.0000000001;  // 1 in 10 billion - ultra low false positive
const UPDATE_INTERVAL: usize = 10_000;

#[derive(Clone, Copy)]
struct AddrTypes { p2pkh: bool, p2sh: bool, p2wpkh: bool, p2tr: bool }
struct Match { pk: [u8; 32], t: &'static str, a: String }

#[repr(C, align(64))]
struct WorkerBuffers {
    pubkey_ser: [u8; 33],
    hash160: [u8; 20],
    witness_prog: [u8; 22],
    base58_buf: [u8; 25],
}
impl WorkerBuffers {
    fn new() -> Self {
        Self { pubkey_ser: [0u8; 33], hash160: [0u8; 20], witness_prog: [0u8; 22], base58_buf: [0u8; 25] }
    }
}

fn main() {
    let threads = num_cpus::get_physical().max(2);
    println!("\n======================================================================");
    println!("        RUSTYWALLET CHECKER v9.0 - ULTRA OPTIMIZED");
    println!("======================================================================\n");
    print!("[1/3] Analyzing... ");
    let _ = stdout().flush();
    let (count, types) = analyze("addresses.txt");
    if count == 0 { println!("No addresses!"); return; }
    let active = [types.p2pkh, types.p2sh, types.p2wpkh, types.p2tr].iter().filter(|&&x| x).count();
    println!("{} addresses, {} types", fmt(count as u64), active);
    print!("[2/3] Loading bloom filter... ");
    let _ = stdout().flush();
    let start = Instant::now();
    let mut bloom = BloomFilter::new(count, BLOOM_FPR);
    let loaded = load("addresses.txt", &mut bloom);
    let mem = bloom.memory_usage() / 1_000_000;
    println!("{} in {:.1}s (~{}MB)", fmt(loaded), start.elapsed().as_secs_f64(), mem);
    let bloom = Arc::new(bloom);
    
    // VALIDATION TEST: Check if bloom filter works correctly
    println!("\n[TEST] Validating bloom filter...");
    let test_addresses = [
        "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo",
        "3M219KR5vEneNb47ewrPfWyb5jQ2DjxRP6",
        "1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF",
        "bc1q8yj0herd4r4yxszw3nkfvt53433thk0f5qst4g",
    ];
    for addr in &test_addresses {
        let found = bloom.contains(addr.to_lowercase().as_bytes());
        println!("  {} -> {}", addr, if found { "✅ FOUND" } else { "❌ NOT FOUND" });
    }
    // Test with random address that should NOT be in bloom
    let fake_addr = "1FakeAddressNotInBloomFilter12345";
    let fake_found = bloom.contains(fake_addr.to_lowercase().as_bytes());
    println!("  {} -> {}", fake_addr, if fake_found { "⚠️ FALSE POSITIVE" } else { "✅ CORRECTLY NOT FOUND" });
    
    // VALIDATION TEST 2: Verify address generation is correct
    println!("\n[TEST] Validating address generation...");
    // Known test vector: private key 1 (0x01)
    let test_sk_bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        b[31] = 1;
        b
    };
    let test_scalar: Scalar = Scalar::from_repr(test_sk_bytes.into()).into_option().unwrap();
    let test_point: ProjectivePoint = ProjectivePoint::GENERATOR * test_scalar;
    let test_affine: AffinePoint = test_point.into();
    let test_encoded = test_affine.to_encoded_point(true);
    let test_pubkey = test_encoded.as_bytes();
    
    // Generate P2PKH address from private key 1
    let mut test_bufs = WorkerBuffers::new();
    let mut test_sha = Sha256::new();
    let mut test_rip = Ripemd160::new();
    test_bufs.pubkey_ser.copy_from_slice(test_pubkey);
    hash160_fast(&test_bufs.pubkey_ser, &mut test_bufs.hash160, &mut test_sha, &mut test_rip);
    
    // Build P2PKH address
    test_bufs.base58_buf[0] = 0x00;
    test_bufs.base58_buf[1..21].copy_from_slice(&test_bufs.hash160);
    let c1 = Sha256::digest(&test_bufs.base58_buf[..21]);
    let c2 = Sha256::digest(&c1);
    test_bufs.base58_buf[21..25].copy_from_slice(&c2[..4]);
    let generated_p2pkh = bs58::encode(&test_bufs.base58_buf[..25]).into_string();
    
    // Known correct P2PKH for private key 1: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
    let expected_p2pkh = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    println!("  Private Key: 0x01");
    println!("  Generated P2PKH: {}", generated_p2pkh);
    println!("  Expected P2PKH:  {}", expected_p2pkh);
    println!("  Match: {}", if generated_p2pkh == expected_p2pkh { "✅ CORRECT" } else { "❌ WRONG" });
    println!();
    let (tx, rx): (Sender<Match>, Receiver<Match>) = bounded(512);
    let att = Arc::new(AtomicU64::new(0));
    let mat = Arc::new(AtomicU64::new(0));
    let chk = Arc::new(AtomicU64::new(0));
    let bal = Arc::new(AtomicU64::new(0));
    let run = Arc::new(AtomicBool::new(true));
    println!("[3/3] {} threads | {}K batch | secp256k1", threads, BATCH_SIZE/1_000);
    println!();
    println!("----------------------------------------------------------------------");
    let t0 = Instant::now();
    let mut hs = vec![];
    for _ in 0..threads {
        let b = Arc::clone(&bloom);
        let a = Arc::clone(&att);
        let m = Arc::clone(&mat);
        let t = tx.clone();
        let r = Arc::clone(&run);
        hs.push(thread::spawn(move || worker_ultra(b, a, m, t, r, types)));
    }
    drop(tx);
    let c = Arc::clone(&chk);
    let f = Arc::clone(&bal);
    let r = Arc::clone(&run);
    let checker = thread::spawn(move || balance(rx, c, f, r));
    let a = Arc::clone(&att);
    let m = Arc::clone(&mat);
    let c = Arc::clone(&chk);
    let _f = Arc::clone(&bal);
    let r = Arc::clone(&run);
    let reporter = thread::spawn(move || {
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
    reporter.join().ok();
    let total = att.load(Ordering::Relaxed);
    let elapsed = t0.elapsed().as_secs_f64();
    println!("\n\n======================================================================");
    println!("  {} keys @ {}/s | bloom:{} checked:{} balance:{}",
        fmt(total), fmt((total as f64/elapsed) as u64),
        mat.load(Ordering::Relaxed), chk.load(Ordering::Relaxed), bal.load(Ordering::Relaxed));
    println!("======================================================================");
}
fn analyze(f: &str) -> (usize, AddrTypes) {
    let file = match File::open(f) { Ok(f) => f, Err(_) => return (0, AddrTypes{p2pkh:false,p2sh:false,p2wpkh:false,p2tr:false}) };
    let mut t = AddrTypes{p2pkh:false,p2sh:false,p2wpkh:false,p2tr:false};
    let mut c = 0;
    for l in BufReader::with_capacity(4<<20, file).lines().flatten() {
        let a = l.trim();
        if a.is_empty() || a.starts_with('#') { continue; }
        c += 1;
        if !t.p2pkh && a.starts_with('1') { t.p2pkh = true; }
        if !t.p2sh && a.starts_with('3') { t.p2sh = true; }
        if !t.p2wpkh && a.starts_with("bc1q") { t.p2wpkh = true; }
        if !t.p2tr && a.starts_with("bc1p") { t.p2tr = true; }
    }
    (c, t)
}
fn load(f: &str, b: &mut BloomFilter) -> u64 {
    let file = match File::open(f) { Ok(f) => f, Err(_) => return 0 };
    let mut c = 0u64;
    for l in BufReader::with_capacity(8<<20, file).lines().flatten() {
        let a = l.trim();
        if !a.is_empty() && !a.starts_with('#') { b.insert(a.to_lowercase().as_bytes()); c += 1; }
    }
    c
}

fn worker_ultra(bloom: Arc<BloomFilter>, att: Arc<AtomicU64>, mat: Arc<AtomicU64>,
                tx: Sender<Match>, run: Arc<AtomicBool>, types: AddrTypes) {
    let mut bufs = WorkerBuffers::new();
    let mut sha256_hasher = Sha256::new();
    let mut ripemd_hasher = Ripemd160::new();
    let mut addr_string = String::with_capacity(64);
    let mut la = 0u64;
    let mut lm = 0u64;
    let mut rng = rand::thread_rng();
    
    // Generator point G for EC point addition
    let g: ProjectivePoint = ProjectivePoint::GENERATOR;
    
    while run.load(Ordering::Relaxed) {
        // Generate random starting scalar
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        
        // Create initial scalar and point
        let mut scalar: Scalar = match Scalar::from_repr(sk_bytes.into()).into_option() {
            Some(s) => s,
            None => continue,
        };
        let mut point: ProjectivePoint = g * scalar;
        
        for i in 0..BATCH_SIZE {
            if i % UPDATE_INTERVAL == 0 {
                if !run.load(Ordering::Relaxed) { break; }
                att.fetch_add(la, Ordering::Relaxed);
                mat.fetch_add(lm, Ordering::Relaxed);
                la = 0; lm = 0;
            }
            
            // Convert to affine and serialize compressed public key
            let affine: AffinePoint = point.into();
            let encoded = affine.to_encoded_point(true);
            let pubkey_bytes = encoded.as_bytes();
            
            if pubkey_bytes.len() == 33 {
                bufs.pubkey_ser.copy_from_slice(pubkey_bytes);
                hash160_fast(&bufs.pubkey_ser, &mut bufs.hash160, &mut sha256_hasher, &mut ripemd_hasher);
                
                // Get current secret key bytes
                let current_sk: [u8; 32] = scalar.to_repr().into();
                let h160 = bufs.hash160;
                let pubkey_copy = bufs.pubkey_ser;
                
                // Check all address types
                if types.p2pkh { chk_p2pkh_fast(&bloom, &h160, &current_sk, &tx, &mut lm, &mut bufs, &mut addr_string); }
                if types.p2sh { chk_p2sh_fast(&bloom, &h160, &current_sk, &tx, &mut lm, &mut bufs, &mut addr_string, &mut sha256_hasher, &mut ripemd_hasher); }
                if types.p2wpkh { chk_p2wpkh_fast(&bloom, &h160, &current_sk, &tx, &mut lm, &mut addr_string); }
                if types.p2tr { chk_p2tr_fast(&bloom, &pubkey_copy, &current_sk, &tx, &mut lm, &mut addr_string); }
            }
            
            la += 1;
            
            // EC Point Addition: P = P + G (MUCH faster than scalar multiplication!)
            point = point + g;
            scalar = scalar + Scalar::ONE;
        }
        att.fetch_add(la, Ordering::Relaxed);
        mat.fetch_add(lm, Ordering::Relaxed);
        la = 0; lm = 0;
    }
}

#[inline(always)]
fn hash160_fast(data: &[u8; 33], out: &mut [u8; 20], sha: &mut Sha256, rip: &mut Ripemd160) {
    sha.update(data);
    let sha_result = sha.finalize_reset();
    rip.update(&sha_result);
    out.copy_from_slice(&rip.finalize_reset());
}

#[inline(always)]
fn chk_p2pkh_fast(b: &BloomFilter, h160: &[u8; 20], sk: &[u8; 32], tx: &Sender<Match>, m: &mut u64, bufs: &mut WorkerBuffers, addr: &mut String) {
    bufs.base58_buf[0] = 0x00;
    bufs.base58_buf[1..21].copy_from_slice(h160);
    let c1 = Sha256::digest(&bufs.base58_buf[..21]);
    let c2 = Sha256::digest(&c1);
    bufs.base58_buf[21..25].copy_from_slice(&c2[..4]);
    addr.clear();
    addr.push_str(&bs58::encode(&bufs.base58_buf[..25]).into_string());
    if b.contains(addr.to_lowercase().as_bytes()) {
        *m += 1; 
        let _ = tx.try_send(Match { pk: *sk, t: "P2PKH", a: addr.clone() });
    }
}

#[inline(always)]
fn chk_p2sh_fast(b: &BloomFilter, h160: &[u8; 20], sk: &[u8; 32], tx: &Sender<Match>, m: &mut u64, bufs: &mut WorkerBuffers, addr: &mut String, sha: &mut Sha256, rip: &mut Ripemd160) {
    bufs.witness_prog[0] = 0x00;
    bufs.witness_prog[1] = 0x14;
    bufs.witness_prog[2..22].copy_from_slice(h160);
    sha.update(&bufs.witness_prog);
    let h3 = sha.finalize_reset();
    rip.update(&h3);
    let h4 = rip.finalize_reset();
    bufs.base58_buf[0] = 0x05;
    bufs.base58_buf[1..21].copy_from_slice(&h4);
    let c1 = Sha256::digest(&bufs.base58_buf[..21]);
    let c2 = Sha256::digest(&c1);
    bufs.base58_buf[21..25].copy_from_slice(&c2[..4]);
    addr.clear();
    addr.push_str(&bs58::encode(&bufs.base58_buf[..25]).into_string());
    if b.contains(addr.to_lowercase().as_bytes()) {
        *m += 1; 
        let _ = tx.try_send(Match { pk: *sk, t: "P2SH", a: addr.clone() });
    }
}

#[inline(always)]
fn chk_p2wpkh_fast(b: &BloomFilter, h160: &[u8; 20], sk: &[u8; 32], tx: &Sender<Match>, m: &mut u64, addr: &mut String) {
    addr.clear();
    bech32_encode_to(addr, "bc", 0, h160);
    if b.contains(addr.to_lowercase().as_bytes()) {
        *m += 1; 
        let _ = tx.try_send(Match { pk: *sk, t: "P2WPKH", a: addr.clone() });
    }
}

#[inline(always)]
fn chk_p2tr_fast(b: &BloomFilter, pk: &[u8; 33], sk: &[u8; 32], tx: &Sender<Match>, m: &mut u64, addr: &mut String) {
    addr.clear();
    bech32m_encode_to(addr, "bc", 1, &pk[1..33]);
    if b.contains(addr.to_lowercase().as_bytes()) {
        *m += 1; 
        let _ = tx.try_send(Match { pk: *sk, t: "P2TR", a: addr.clone() });
    }
}

#[inline(always)]
fn bech32_encode_to(out: &mut String, hrp: &str, version: u8, data: &[u8]) {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    out.push_str(hrp); out.push('1');
    let mut values = [0u8; 65]; let mut idx = 0;
    values[idx] = version; idx += 1;
    let mut acc = 0u32; let mut bits = 0u32;
    for &b in data { acc = (acc << 8) | b as u32; bits += 8; while bits >= 5 { bits -= 5; values[idx] = ((acc >> bits) & 31) as u8; idx += 1; } }
    if bits > 0 { values[idx] = ((acc << (5 - bits)) & 31) as u8; idx += 1; }
    let checksum = bech32_checksum_fast(hrp, &values[..idx], 1);
    for i in 0..idx { out.push(CHARSET[values[i] as usize] as char); }
    for c in checksum { out.push(CHARSET[c as usize] as char); }
}
#[inline(always)]
fn bech32m_encode_to(out: &mut String, hrp: &str, version: u8, data: &[u8]) {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    out.push_str(hrp); out.push('1');
    let mut values = [0u8; 65]; let mut idx = 0;
    values[idx] = version; idx += 1;
    let mut acc = 0u32; let mut bits = 0u32;
    for &b in data { acc = (acc << 8) | b as u32; bits += 8; while bits >= 5 { bits -= 5; values[idx] = ((acc >> bits) & 31) as u8; idx += 1; } }
    if bits > 0 { values[idx] = ((acc << (5 - bits)) & 31) as u8; idx += 1; }
    let checksum = bech32_checksum_fast(hrp, &values[..idx], 0x2bc830a3);
    for i in 0..idx { out.push(CHARSET[values[i] as usize] as char); }
    for c in checksum { out.push(CHARSET[c as usize] as char); }
}
#[inline(always)]
fn bech32_checksum_fast(hrp: &str, data: &[u8], constant: u32) -> [u8; 6] {
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

fn balance(rx: Receiver<Match>, chk: Arc<AtomicU64>, bal: Arc<AtomicU64>, run: Arc<AtomicBool>) {
    let rt = Runtime::new().unwrap();
    while run.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(m) => {
                chk.fetch_add(1, Ordering::Relaxed);
                let addr = m.a.clone();
                
                // Check balance via API
                let balance_result = rt.block_on(async {
                    check_btc_balance(&addr).await
                });
                
                match balance_result {
                    Ok(b) => {
                        let has_bal = b.balance > 0 || b.unconfirmed != 0;
                        
                        // Always save with balance info
                        save_with_balance_info(&m, &b);
                        
                        // Print to terminal
                        println!("\n[🔍] BLOOM MATCH: {} | Balance: {} sat | Unconfirmed: {} sat", 
                            addr, fmt(b.balance), b.unconfirmed);
                        
                        if has_bal {
                            bal.fetch_add(1, Ordering::Relaxed);
                            println!("[💰💰💰] BALANCE FOUND! {} | {} sat", addr, fmt(b.balance));
                            save_balance_found(&m, &b);
                        }
                    }
                    Err(e) => {
                        // Save even if API error, mark as unchecked
                        save_api_error(&m, &e.to_string());
                        println!("\n[⚠️] API Error for {}: {}", addr, e);
                    }
                }
                
                thread::sleep(Duration::from_millis(1000 / BALANCE_CHECK_RATE));
            }
            Err(_) => continue,
        }
    }
    // Process remaining items in queue
    for m in rx.try_iter() { 
        let addr = m.a.clone();
        let balance_result = rt.block_on(async {
            check_btc_balance(&addr).await
        });
        if let Ok(b) = balance_result {
            save_with_balance_info(&m, &b);
        }
    }
}

fn save_with_balance_info(m: &Match, b: &BitcoinBalance) {
    let pk = PrivateKey::from_bytes(m.pk).unwrap();
    let wif = pk.to_wif(rustywallet_keys::prelude::Network::Mainnet);
    let hex_key = hex::encode(&m.pk);
    let pubkey = pk.public_key();
    let pubkey_hex = hex::encode(pubkey.to_compressed());
    let pubkey_uncompressed = hex::encode(pubkey.to_uncompressed());
    
    let mut f = OpenOptions::new().create(true).append(true).open("found.txt").unwrap();
    writeln!(f, "================================================================================").ok();
    writeln!(f, "Type: {}", m.t).ok();
    writeln!(f, "Address: {}", m.a).ok();
    writeln!(f, "Balance: {} satoshis ({:.8} BTC)", b.balance, b.balance as f64 / 100_000_000.0).ok();
    writeln!(f, "Unconfirmed: {} satoshis", b.unconfirmed).ok();
    writeln!(f, "Total Received: {} satoshis", b.total_received).ok();
    writeln!(f, "Total Sent: {} satoshis", b.total_sent).ok();
    writeln!(f, "TX Count: {}", b.tx_count).ok();
    writeln!(f, "Private Key (HEX): {}", hex_key).ok();
    writeln!(f, "Private Key (WIF): {}", wif).ok();
    writeln!(f, "Public Key (Compressed): {}", pubkey_hex).ok();
    writeln!(f, "Public Key (Uncompressed): {}", pubkey_uncompressed).ok();
    writeln!(f, "Timestamp: {:?}", std::time::SystemTime::now()).ok();
    writeln!(f, "================================================================================").ok();
    writeln!(f, "").ok();
}

fn save_balance_found(m: &Match, b: &BitcoinBalance) {
    let pk = PrivateKey::from_bytes(m.pk).unwrap();
    let wif = pk.to_wif(rustywallet_keys::prelude::Network::Mainnet);
    let hex_key = hex::encode(&m.pk);
    let pubkey = pk.public_key();
    let pubkey_hex = hex::encode(pubkey.to_compressed());
    let pubkey_uncompressed = hex::encode(pubkey.to_uncompressed());
    
    let mut f = OpenOptions::new().create(true).append(true).open("found_with_balance.txt").unwrap();
    writeln!(f, "********************************************************************************").ok();
    writeln!(f, "*** 💰💰💰 BALANCE FOUND! 💰💰💰 ***").ok();
    writeln!(f, "********************************************************************************").ok();
    writeln!(f, "Type: {}", m.t).ok();
    writeln!(f, "Address: {}", m.a).ok();
    writeln!(f, "Balance: {} satoshis ({:.8} BTC)", b.balance, b.balance as f64 / 100_000_000.0).ok();
    writeln!(f, "Unconfirmed: {} satoshis", b.unconfirmed).ok();
    writeln!(f, "Total Received: {} satoshis", b.total_received).ok();
    writeln!(f, "Total Sent: {} satoshis", b.total_sent).ok();
    writeln!(f, "TX Count: {}", b.tx_count).ok();
    writeln!(f, "Private Key (HEX): {}", hex_key).ok();
    writeln!(f, "Private Key (WIF): {}", wif).ok();
    writeln!(f, "Public Key (Compressed): {}", pubkey_hex).ok();
    writeln!(f, "Public Key (Uncompressed): {}", pubkey_uncompressed).ok();
    writeln!(f, "Timestamp: {:?}", std::time::SystemTime::now()).ok();
    writeln!(f, "********************************************************************************").ok();
    writeln!(f, "").ok();
}

fn save_api_error(m: &Match, error: &str) {
    let pk = PrivateKey::from_bytes(m.pk).unwrap();
    let wif = pk.to_wif(rustywallet_keys::prelude::Network::Mainnet);
    let hex_key = hex::encode(&m.pk);
    let pubkey = pk.public_key();
    let pubkey_hex = hex::encode(pubkey.to_compressed());
    let pubkey_uncompressed = hex::encode(pubkey.to_uncompressed());
    
    let mut f = OpenOptions::new().create(true).append(true).open("found.txt").unwrap();
    writeln!(f, "================================================================================").ok();
    writeln!(f, "Type: {}", m.t).ok();
    writeln!(f, "Address: {}", m.a).ok();
    writeln!(f, "Balance: API ERROR - {}", error).ok();
    writeln!(f, "Private Key (HEX): {}", hex_key).ok();
    writeln!(f, "Private Key (WIF): {}", wif).ok();
    writeln!(f, "Public Key (Compressed): {}", pubkey_hex).ok();
    writeln!(f, "Public Key (Uncompressed): {}", pubkey_uncompressed).ok();
    writeln!(f, "Timestamp: {:?}", std::time::SystemTime::now()).ok();
    writeln!(f, "================================================================================").ok();
    writeln!(f, "").ok();
}

fn fmt(n: u64) -> String {
    let s = n.to_string();
    let mut r = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { r.push(','); }
        r.push(c);
    }
    r.chars().rev().collect()
}
