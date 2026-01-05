use rustywallet_keys::prelude::Network;
use rustywallet_vanity::prelude::*;
use std::time::Duration;

fn main() {
    println!("=== rustywallet-vanity Demo ===\n");

    // 0. Test 1NirvaGoldST2010
    println!("0. Difficulty Estimation for '1NirvaGoldST2010'");
    let gen = VanityGenerator::new().pattern("1NirvaGoldST2010");
    let est = &gen.estimate_difficulty()[0];
    println!("   Pattern: 1NirvaGoldST2010 (15 chars after '1')");
    println!("   Difficulty: {}", est.difficulty_level);
    println!("   Expected attempts: {:.2e}", est.expected_attempts as f64);
    println!("   Estimated time: {:?}", est.estimated_time);
    if let Some(warning) = est.warning() {
        println!("   ⚠️  {}", warning);
    }
    println!();

    // Try shorter prefix
    println!("   Trying shorter prefixes:");
    for prefix in ["1N", "1Ni", "1Nir", "1Nirv", "1Nirva"] {
        let gen = VanityGenerator::new().pattern(prefix);
        let est = &gen.estimate_difficulty()[0];
        println!("   '{}': {} (~{:.0} attempts, ~{:?})", 
            prefix, est.difficulty_level, est.expected_attempts as f64, est.estimated_time);
    }
    println!();

    // Actually search for 1Nirva (6 chars = ~380M attempts)
    println!("   Searching for '1Nirva' (case-insensitive)...");
    let result = VanityGenerator::new()
        .pattern("1Nirva")
        .case_insensitive()
        .max_attempts(50_000_000)
        .timeout(Duration::from_secs(120))
        .search_with_progress(|p| {
            print!("\r   Checked {} keys ({:.0} keys/sec)...", p.attempts, p.rate);
        });
    
    println!();
    match result {
        Ok(r) => {
            println!("   ✅ Found: {}", r.address);
            println!("   Private Key: {}", r.private_key.to_wif(Network::Mainnet));
            println!("   Attempts: {}", r.stats.attempts);
        }
        Err(VanityError::MaxAttemptsReached(n)) => {
            println!("   ⏳ Max attempts ({}) reached", n);
        }
        Err(VanityError::Timeout(d)) => {
            println!("   ⏳ Timeout ({:?})", d);
        }
        Err(e) => println!("   ❌ Error: {}", e),
    }
    println!();

    // 1. Simple prefix search
    println!("1. Simple Prefix Search (1A)");
    println!("   Searching for address starting with '1A'...");
    
    let result = VanityGenerator::new()
        .pattern("1A")
        .address_type(AddressType::P2PKH)
        .search_parallel()
        .unwrap();
    
    println!("   ✅ Found!");
    println!("   Address:     {}", result.address);
    println!("   Private Key: {}", result.private_key.to_wif(Network::Mainnet));
    println!("   Attempts:    {}", result.stats.attempts);
    println!("   Time:        {:?}", result.stats.elapsed);
    println!("   Rate:        {:.0} keys/sec", result.stats.rate);
    println!();

    // 2. Difficulty estimation
    println!("2. Difficulty Estimation");
    let patterns = ["1A", "1AB", "1ABC", "1Love"];
    for p in patterns {
        let gen = VanityGenerator::new().pattern(p);
        let est = &gen.estimate_difficulty()[0];
        println!("   Pattern '{}': {} (expected ~{} attempts)", 
            p, est.difficulty_level, est.expected_attempts);
    }
    println!();

    // 3. Multi-pattern search
    println!("3. Multi-Pattern Search");
    println!("   Searching for '1BTC', '1ETH', or '1XRP'...");
    
    let result = VanityGenerator::new()
        .patterns(&["1BTC", "1ETH", "1XRP"])
        .case_insensitive()
        .max_attempts(1_000_000)
        .timeout(Duration::from_secs(30))
        .search_parallel();
    
    match result {
        Ok(r) => {
            println!("   ✅ Found: {} (matched {})", r.address, r.matched_pattern);
            println!("   Attempts: {}", r.stats.attempts);
        }
        Err(VanityError::MaxAttemptsReached(n)) => {
            println!("   ⏳ Max attempts ({}) reached - pattern is difficult", n);
        }
        Err(VanityError::Timeout(d)) => {
            println!("   ⏳ Timeout ({:?}) - pattern is difficult", d);
        }
        Err(e) => println!("   ❌ Error: {}", e),
    }
    println!();

    // 4. SegWit address
    println!("4. SegWit Address (bc1q)");
    println!("   Searching for address starting with 'bc1qa'...");
    
    let result = VanityGenerator::new()
        .pattern("bc1qa")
        .address_type(AddressType::P2WPKH)
        .search_parallel()
        .unwrap();
    
    println!("   ✅ Found: {}", result.address);
    println!("   Attempts: {}", result.stats.attempts);
    println!();

    // 5. Ethereum address
    println!("5. Ethereum Address (0x)");
    println!("   Searching for address starting with '0xdead' (case-insensitive)...");
    
    let result = VanityGenerator::new()
        .pattern("0xdead")
        .address_type(AddressType::Ethereum)
        .case_insensitive()
        .max_attempts(10_000_000)
        .search_parallel();
    
    match result {
        Ok(r) => {
            println!("   ✅ Found: {}", r.address);
            println!("   Attempts: {}", r.stats.attempts);
        }
        Err(VanityError::MaxAttemptsReached(_)) => {
            println!("   ⏳ Pattern '0xdead' is difficult (4 hex chars = 65536 expected)");
        }
        Err(e) => println!("   ❌ Error: {}", e),
    }
    println!();

    // 6. Progress callback
    println!("6. Progress Callback");
    println!("   Searching with progress updates...");
    
    let result = VanityGenerator::new()
        .pattern("1AB")
        .address_type(AddressType::P2PKH)
        .batch_size(50_000)
        .search_with_progress(|progress| {
            print!("\r   Checked {} keys ({:.0} keys/sec)...", 
                progress.attempts, progress.rate);
        });
    
    println!();
    if let Ok(r) = result {
        println!("   ✅ Found: {}", r.address);
    }
    println!();

    // 7. Validation test
    println!("7. Key Validation");
    let result = VanityGenerator::new()
        .pattern("1")
        .search()
        .unwrap();
    
    // Verify the key produces the address
    let derived = AddressType::P2PKH
        .derive_address(&result.private_key, false)
        .unwrap();
    
    let valid = derived == result.address;
    println!("   Address:  {}", result.address);
    println!("   Derived:  {}", derived);
    println!("   Match:    {} {}", if valid { "✅" } else { "❌" }, if valid { "PASS" } else { "FAIL" });
    
    println!("\n=== Demo Complete ===");
}
