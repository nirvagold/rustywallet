use anyhow::{anyhow, Result};
use colored::Colorize;
use rustywallet::signer::{
    bitcoin::verify_bitcoin_message,
    ethereum::{format_address, recover_ethereum_address},
    signature::{RecoverableSignature, Signature},
};

pub fn run(address: &str, message: &str, signature: &str, format: &str) -> Result<()> {
    println!("{}", "Signature Verification".bold());
    println!();
    println!("  {} \"{}\"", "Message:".bold(), message);
    println!("  {} {}", "Address:".bold(), address);
    println!("  {} {}", "Format:".bold(), format);
    println!();

    match format {
        "bitcoin" => {
            let is_valid = verify_bitcoin_message(address, message, signature)
                .map_err(|e| anyhow!("Verification failed: {}", e))?;
            if is_valid {
                println!("{} {}", "✓".green().bold(), "Signature is valid!".green());
            } else {
                println!("{} {}", "✗".red().bold(), "Signature is invalid!".red());
            }
        }
        "ethereum" => {
            // Parse signature
            let sig_hex = signature.strip_prefix("0x").unwrap_or(signature);
            let sig_bytes =
                hex::decode(sig_hex).map_err(|e| anyhow!("Invalid signature hex: {}", e))?;

            if sig_bytes.len() != 65 {
                return Err(anyhow!("Invalid signature length: expected 65 bytes"));
            }

            // Parse r, s, v
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            r.copy_from_slice(&sig_bytes[..32]);
            s.copy_from_slice(&sig_bytes[32..64]);
            let v = sig_bytes[64];

            // Convert v to recovery id (v is 27/28 or 0/1)
            let recovery_id = if v >= 27 { v - 27 } else { v };

            let sig = Signature::new(r, s);
            let recoverable = RecoverableSignature::new(sig, recovery_id)
                .map_err(|e| anyhow!("Invalid signature: {}", e))?;

            match recover_ethereum_address(&recoverable, message.as_bytes()) {
                Ok(recovered) => {
                    let recovered_str = format_address(&recovered);
                    let expected = address.to_lowercase();
                    let recovered_lower = recovered_str.to_lowercase();

                    if expected == recovered_lower {
                        println!("{} {}", "✓".green().bold(), "Signature is valid!".green());
                        println!();
                        println!("  {} {}", "Recovered:".bold(), recovered_str);
                    } else {
                        println!("{} {}", "✗".red().bold(), "Signature is invalid!".red());
                        println!();
                        println!("  {} {}", "Expected:".bold(), address);
                        println!("  {} {}", "Recovered:".bold(), recovered_str);
                    }
                }
                Err(e) => {
                    println!(
                        "{} {}",
                        "✗".red().bold(),
                        "Failed to recover address!".red()
                    );
                    return Err(anyhow!("Recovery failed: {}", e));
                }
            }
        }
        _ => return Err(anyhow!("Invalid format: {}", format)),
    }

    Ok(())
}
