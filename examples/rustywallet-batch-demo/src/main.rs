use rustywallet_batch::prelude::*;
use rustywallet_keys::prelude::*;
use std::time::Instant;

fn main() {
    println!("=== rustywallet-batch Demo ===\n");

    // 0. Single Key Validation - Full Format Check
    println!("0. Single Key Validation (Full Format Check)");
    println!("   ----------------------------------------");
    
    let key = BatchGenerator::new()
        .count(1)
        .generate_vec()
        .unwrap()
        .pop()
        .unwrap();
    
    // Private Key formats
    println!("\n   [Private Key]");
    println!("   Hex (64 chars):     {}", key.to_hex());
    println!("   Bytes (32 bytes):   {:?}", &key.to_bytes()[..8]); // Show first 8 bytes
    println!("   WIF (Mainnet):      {}", key.to_wif(Network::Mainnet));
    println!("   WIF (Testnet):      {}", key.to_wif(Network::Testnet));
    
    // Derive public key
    let pubkey = key.public_key();
    
    println!("\n   [Public Key]");
    println!("   Compressed (33 bytes):   {}", hex::encode(pubkey.to_compressed()));
    println!("   Uncompressed (65 bytes): {}...", &hex::encode(pubkey.to_uncompressed())[..40]);
    
    // Validate round-trip
    println!("\n   [Validation]");
    
    // Hex round-trip
    let recovered_hex = PrivateKey::from_hex(&key.to_hex()).unwrap();
    let hex_valid = recovered_hex.to_hex() == key.to_hex();
    println!("   Hex round-trip:     {} {}", if hex_valid { "✅" } else { "❌" }, 
        if hex_valid { "PASS" } else { "FAIL" });
    
    // Bytes round-trip
    let recovered_bytes = PrivateKey::from_bytes(key.to_bytes()).unwrap();
    let bytes_valid = recovered_bytes.to_hex() == key.to_hex();
    println!("   Bytes round-trip:   {} {}", if bytes_valid { "✅" } else { "❌" },
        if bytes_valid { "PASS" } else { "FAIL" });
    
    // WIF round-trip
    let wif = key.to_wif(Network::Mainnet);
    let recovered_wif = PrivateKey::from_wif(&wif).unwrap();
    let wif_valid = recovered_wif.to_hex() == key.to_hex();
    println!("   WIF round-trip:     {} {}", if wif_valid { "✅" } else { "❌" },
        if wif_valid { "PASS" } else { "FAIL" });
    
    // Public key derivation consistency
    let pubkey2 = recovered_hex.public_key();
    let pubkey_valid = pubkey.to_compressed() == pubkey2.to_compressed();
    println!("   PubKey derivation:  {} {}", if pubkey_valid { "✅" } else { "❌" },
        if pubkey_valid { "PASS" } else { "FAIL" });
    
    // Key validity check
    let is_valid = PrivateKey::is_valid(&key.to_bytes());
    println!("   Key validity:       {} {}", if is_valid { "✅" } else { "❌" },
        if is_valid { "PASS" } else { "FAIL" });
    
    println!("\n   ----------------------------------------\n");

    // 1. Basic batch generation
    println!("1. Basic Batch Generation (1000 keys)");
    let start = Instant::now();
    let keys = BatchGenerator::new()
        .count(1000)
        .generate_vec()
        .unwrap();
    let elapsed = start.elapsed();
    println!("   Generated {} keys in {:?}", keys.len(), elapsed);
    println!("   First key: {}", keys[0].to_hex());
    println!("   Last key:  {}", keys[keys.len()-1].to_hex());
    println!();

    // 2. Parallel batch generation
    println!("2. Parallel Batch Generation (100,000 keys)");
    let start = Instant::now();
    let keys = BatchGenerator::new()
        .count(100_000)
        .parallel()
        .generate_vec()
        .unwrap();
    let elapsed = start.elapsed();
    let rate = keys.len() as f64 / elapsed.as_secs_f64();
    println!("   Generated {} keys in {:?}", keys.len(), elapsed);
    println!("   Rate: {:.0} keys/sec", rate);
    println!();

    // 3. Streaming (memory efficient)
    println!("3. Streaming Mode (take first 10 from 1M stream)");
    let stream = BatchGenerator::new()
        .count(1_000_000)
        .generate()
        .unwrap();
    
    println!("   Stream created for 1M keys");
    for (i, key) in stream.take(10).enumerate() {
        println!("   Key {}: {}", i + 1, key.unwrap().to_hex());
    }
    println!();

    // 4. Key Scanner (incremental)
    println!("4. Key Scanner (Forward from key 1)");
    let base = PrivateKey::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001"
    ).unwrap();
    
    let scanner = KeyScanner::new(base.clone())
        .direction(ScanDirection::Forward);
    
    for (i, key) in scanner.scan_range(5).enumerate() {
        println!("   Key {}: {}", i + 1, key.unwrap().to_hex());
    }
    println!();

    // 5. Key Scanner (Backward)
    println!("5. Key Scanner (Backward from key 100)");
    let base = PrivateKey::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000064" // 100 in hex
    ).unwrap();
    
    let scanner = KeyScanner::new(base)
        .direction(ScanDirection::Backward);
    
    for (i, key) in scanner.scan_range(5).enumerate() {
        let k = key.unwrap();
        println!("   Key {}: {} (decimal: {})", i + 1, k.to_hex(), k.to_decimal());
    }
    println!();

    // 6. Configuration presets
    println!("6. Configuration Presets");
    let fast = BatchConfig::fast();
    let balanced = BatchConfig::balanced();
    let memory = BatchConfig::memory_efficient();
    
    println!("   Fast:     batch_size={}, parallel={}, chunk_size={}", 
        fast.batch_size, fast.parallel, fast.chunk_size);
    println!("   Balanced: batch_size={}, parallel={}, chunk_size={}", 
        balanced.batch_size, balanced.parallel, balanced.chunk_size);
    println!("   Memory:   batch_size={}, parallel={}, chunk_size={}", 
        memory.batch_size, memory.parallel, memory.chunk_size);
    println!();

    // 7. Performance benchmark
    println!("7. Performance Benchmark (1M keys parallel)");
    let start = Instant::now();
    let keys = BatchGenerator::new()
        .count(1_000_000)
        .parallel()
        .generate_vec()
        .unwrap();
    let elapsed = start.elapsed();
    let rate = keys.len() as f64 / elapsed.as_secs_f64();
    println!("   Generated {} keys in {:?}", keys.len(), elapsed);
    println!("   Rate: {:.0} keys/sec", rate);
    
    if rate >= 1_000_000.0 {
        println!("   ✅ Target achieved: 1M+ keys/sec!");
    } else {
        println!("   ⚠️  Below target (1M keys/sec) - random generation is CPU-bound");
    }

    // 8. Incremental Key Generation (FAST!)
    println!("\n8. Incremental Key Generation (1M keys)");
    let base = PrivateKey::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001"
    ).unwrap();
    
    let start = Instant::now();
    let keys = IncrementalKeyGenerator::from_key(&base, 1_000_000).generate();
    let elapsed = start.elapsed();
    let rate = keys.len() as f64 / elapsed.as_secs_f64();
    println!("   Generated {} keys in {:?}", keys.len(), elapsed);
    println!("   Rate: {:.0} keys/sec", rate);
    
    if rate >= 1_000_000.0 {
        println!("   ✅ Target achieved: 1M+ keys/sec!");
    } else {
        println!("   ⚠️  Below target (1M keys/sec)");
    }
    
    println!("\n=== Demo Complete ===");
}
