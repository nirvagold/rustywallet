# Vanity Address Generation

This guide covers generating custom Bitcoin addresses with specific patterns using `rustywallet-vanity`.

## What are Vanity Addresses?

Vanity addresses contain human-readable patterns:
- `1Love...` - Starts with "Love"
- `bc1qcafe...` - Contains "cafe"
- `1BTC...` - Starts with "BTC"

## Basic Usage

### Simple Prefix Search

```rust
use rustywallet_vanity::{VanityGenerator, VanityConfig, Pattern};

let config = VanityConfig::default();
let generator = VanityGenerator::new(config);

// Find address starting with "1Love"
let result = generator.find(Pattern::prefix("Love"))?;

println!("Address: {}", result.address);
println!("Private Key: {}", result.private_key_wif());
println!("Attempts: {}", result.attempts);
println!("Time: {:?}", result.duration);
```

### Case-Insensitive Search

```rust
let result = generator.find(Pattern::prefix_case_insensitive("love"))?;
// Matches: 1Love..., 1LOVE..., 1LoVe..., etc.
```

### Contains Pattern

```rust
// Find address containing "cafe" anywhere
let result = generator.find(Pattern::contains("cafe"))?;
```

### Suffix Pattern

```rust
// Find address ending with "btc"
let result = generator.find(Pattern::suffix("btc"))?;
```

## Address Types

### Legacy (P2PKH)

```rust
use rustywallet_vanity::AddressType;

let config = VanityConfig {
    address_type: AddressType::P2PKH,
    ..Default::default()
};

let generator = VanityGenerator::new(config);
let result = generator.find(Pattern::prefix("Love"))?;
// Result: 1Love...
```

### Native SegWit (P2WPKH)

```rust
let config = VanityConfig {
    address_type: AddressType::P2WPKH,
    ..Default::default()
};

let generator = VanityGenerator::new(config);
let result = generator.find(Pattern::prefix("cafe"))?;
// Result: bc1qcafe...
```

### Taproot (P2TR)

```rust
let config = VanityConfig {
    address_type: AddressType::P2TR,
    ..Default::default()
};

let generator = VanityGenerator::new(config);
let result = generator.find(Pattern::prefix("abc"))?;
// Result: bc1pabc...
```

## Difficulty Estimation

Estimate time before starting:

```rust
use rustywallet_vanity::estimate_difficulty;

let pattern = "Love";
let difficulty = estimate_difficulty(pattern, AddressType::P2PKH);

println!("Pattern: {}", pattern);
println!("Difficulty: 1 in {}", difficulty.odds);
println!("Estimated attempts: {}", difficulty.expected_attempts);
println!("Estimated time: {:?}", difficulty.estimated_time);
```

### Difficulty Reference

| Pattern Length | Odds | ~Time (8 cores) |
|----------------|------|-----------------|
| 1 char | 1:58 | <1 second |
| 2 chars | 1:3,364 | <1 second |
| 3 chars | 1:195,112 | ~1 second |
| 4 chars | 1:11M | ~30 seconds |
| 5 chars | 1:656M | ~30 minutes |
| 6 chars | 1:38B | ~1 day |
| 7 chars | 1:2.2T | ~2 months |

Note: Base58 has 58 characters, so each additional character multiplies difficulty by ~58.

## Multi-threaded Search

```rust
let config = VanityConfig {
    threads: 8,  // Use 8 threads
    ..Default::default()
};

let generator = VanityGenerator::new(config);
let result = generator.find(Pattern::prefix("Love"))?;
```

### Auto-detect Cores

```rust
let config = VanityConfig {
    threads: 0,  // Auto-detect (uses all cores)
    ..Default::default()
};
```

## Progress Tracking

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

let counter = Arc::new(AtomicU64::new(0));
let counter_clone = counter.clone();

let config = VanityConfig::default();
let generator = VanityGenerator::new(config);

// With progress callback
let result = generator.find_with_progress(
    Pattern::prefix("Love"),
    move |attempts| {
        let total = counter_clone.fetch_add(attempts, Ordering::Relaxed);
        if total % 1_000_000 == 0 {
            println!("Searched: {} addresses", total);
        }
    }
)?;
```

## Timeout and Limits

### Set Maximum Attempts

```rust
let config = VanityConfig {
    max_attempts: Some(100_000_000),  // Stop after 100M attempts
    ..Default::default()
};

let generator = VanityGenerator::new(config);

match generator.find(Pattern::prefix("LongPattern")) {
    Ok(result) => println!("Found: {}", result.address),
    Err(VanityError::MaxAttemptsReached) => {
        println!("Pattern not found within limit");
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

### Set Timeout

```rust
use std::time::Duration;

let config = VanityConfig {
    timeout: Some(Duration::from_secs(60)),  // 1 minute timeout
    ..Default::default()
};
```

## Multiple Patterns

Search for any of multiple patterns:

```rust
let patterns = vec![
    Pattern::prefix("Love"),
    Pattern::prefix("BTC"),
    Pattern::prefix("Cafe"),
];

let result = generator.find_any(&patterns)?;
println!("Found: {} (matched pattern: {})", result.address, result.matched_pattern);
```

## Batch Vanity Generation

Find multiple vanity addresses:

```rust
// Find 10 addresses starting with "1A"
let results = generator.find_multiple(Pattern::prefix("A"), 10)?;

for result in results {
    println!("{}: {}", result.address, result.private_key_wif());
}
```

## Valid Characters

### P2PKH (Legacy)

Valid after the leading `1`:
```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

Note: No `0`, `O`, `I`, `l` (to avoid confusion).

### Bech32 (SegWit/Taproot)

Valid after `bc1q` or `bc1p`:
```
023456789acdefghjklmnpqrstuvwxyz
```

Note: Lowercase only, no `1`, `b`, `i`, `o`.

## Error Handling

```rust
use rustywallet_vanity::{VanityGenerator, VanityConfig, Pattern, VanityError};

let generator = VanityGenerator::new(VanityConfig::default());

match generator.find(Pattern::prefix("0OIl")) {
    Ok(result) => println!("Found: {}", result.address),
    Err(VanityError::InvalidPattern(msg)) => {
        eprintln!("Invalid pattern: {}", msg);
    }
    Err(VanityError::MaxAttemptsReached) => {
        eprintln!("Max attempts reached");
    }
    Err(VanityError::Timeout) => {
        eprintln!("Search timed out");
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

## Security Considerations

1. **Generate locally** - Never use online vanity generators
2. **Verify the address** - Ensure it matches your pattern
3. **Backup immediately** - Save the private key securely
4. **Don't share patterns** - Attackers could pre-generate

```rust
// GOOD: Generate locally
let result = generator.find(Pattern::prefix("Love"))?;

// BAD: Using online service
// let result = online_vanity_service("Love")?;  // Don't do this!
```

## Performance Tips

1. **Use all CPU cores** - Set `threads: 0` for auto-detect
2. **Keep patterns short** - Each character adds ~58x difficulty
3. **Use case-insensitive** - Doubles your chances
4. **Prefer prefix over contains** - Faster to check
5. **Consider bech32** - Fewer valid characters = easier patterns

## Example: Complete Workflow

```rust
use rustywallet_vanity::{
    VanityGenerator, VanityConfig, Pattern, AddressType,
    estimate_difficulty,
};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pattern = "cafe";
    let address_type = AddressType::P2WPKH;
    
    // 1. Estimate difficulty
    let difficulty = estimate_difficulty(pattern, address_type);
    println!("Searching for: bc1q{}...", pattern);
    println!("Estimated time: {:?}", difficulty.estimated_time);
    
    // 2. Configure generator
    let config = VanityConfig {
        address_type,
        threads: 0,  // All cores
        timeout: Some(Duration::from_secs(300)),  // 5 min timeout
        ..Default::default()
    };
    
    // 3. Search
    let generator = VanityGenerator::new(config);
    let result = generator.find(Pattern::prefix(pattern))?;
    
    // 4. Display result
    println!("\n=== VANITY ADDRESS FOUND ===");
    println!("Address: {}", result.address);
    println!("Private Key (WIF): {}", result.private_key_wif());
    println!("Attempts: {}", result.attempts);
    println!("Time: {:?}", result.duration);
    println!("============================");
    
    // 5. Verify
    assert!(result.address.starts_with(&format!("bc1q{}", pattern)));
    
    Ok(())
}
```

## Next Steps

- [Batch Generation](./batch-generation.md)
- [Security Best Practices](./security.md)
- [Key Management](../guides/key-management.md)
