use anyhow::{anyhow, Result};
use colored::Colorize;
use rustywallet::mnemonic::{Mnemonic, WordCount};

pub fn run(
    words: &str,
    passphrase: Option<&str>,
    validate: Option<&str>,
    show_seed: bool,
) -> Result<()> {
    // Validate existing mnemonic
    if let Some(phrase) = validate {
        return validate_mnemonic(phrase, passphrase, show_seed);
    }

    // Generate new mnemonic
    let word_count = match words {
        "12" => WordCount::Words12,
        "15" => WordCount::Words15,
        "18" => WordCount::Words18,
        "21" => WordCount::Words21,
        "24" => WordCount::Words24,
        _ => return Err(anyhow!("Invalid word count: {}", words)),
    };

    let mnemonic = Mnemonic::generate(word_count);

    println!("{}", "Generated Mnemonic".bold());
    println!();
    println!("  {} {}", "Phrase:".bold(), mnemonic.to_phrase().green());
    println!("  {} {}", "Words:".bold(), words);

    if show_seed {
        let pass = passphrase.unwrap_or("");
        let seed = mnemonic.to_seed(pass);
        println!();
        println!(
            "  {} {}",
            "Seed:".bold(),
            hex::encode(seed.as_bytes()).yellow()
        );
        if passphrase.is_some() {
            println!("  {} (with passphrase)", "Note:".bold());
        }
    }

    println!();
    println!(
        "{}",
        "⚠️  Write down your mnemonic and keep it safe!".yellow()
    );

    Ok(())
}

fn validate_mnemonic(phrase: &str, passphrase: Option<&str>, show_seed: bool) -> Result<()> {
    match Mnemonic::from_phrase(phrase) {
        Ok(mnemonic) => {
            println!("{} {}", "✓".green().bold(), "Valid mnemonic!".green());
            println!();

            // Count words manually
            let word_count = phrase.split_whitespace().count();
            println!("  {} {}", "Words:".bold(), word_count);

            if show_seed {
                let pass = passphrase.unwrap_or("");
                let seed = mnemonic.to_seed(pass);
                println!();
                println!(
                    "  {} {}",
                    "Seed:".bold(),
                    hex::encode(seed.as_bytes()).yellow()
                );
            }

            Ok(())
        }
        Err(e) => {
            println!("{} {}", "✗".red().bold(), "Invalid mnemonic!".red());
            Err(anyhow!("{}", e))
        }
    }
}
