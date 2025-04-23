use anyhow::{anyhow, Context, Result};
// Common library imports
use common::{
    constants::COMMON_DOMAIN_BIT_LENGTH_ADDITION,
    models::CliSignaturePayload,
    ring::{ring_sign, ring_verify, RingSignature},
    rsa::{
        load_keypair_from_pgp,
        load_public_key_from_pem,
        load_public_key_from_pgp,
        load_secret_key_from_pem, // Import KeyPair
        PublicKey,
        SecretKey,
    },
    serialization::{biguint_to_hex, hex_to_biguint},
};
// BigUint and traits
use num_bigint::BigUint;
// Logging
use log::{debug, error, info};
// CLI interaction
use dialoguer::{Confirm, Input, Password, Select};
use std::fs; // Import the fs module for file writing and reading
use std::io::{stdin, Read};
use std::path::Path; // Import Path for file existence check

fn main() -> Result<()> {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Select mode: Sign or Verify
    let modes = &["Sign", "Verify"];
    let mode_idx = Select::new()
        .with_prompt("Select operation mode")
        .items(modes)
        .default(0)
        .interact()?;

    match modes[mode_idx] {
        "Sign" => handle_sign()?,
        "Verify" => handle_verify()?,
        _ => unreachable!(),
    }

    Ok(())
}

// --- Sign Mode ---
fn handle_sign() -> Result<()> {
    info!("--- Sign Mode ---");

    // Select key file format
    let format_options = &[
        ("PKCS#8 format (*.pem, *.key)", "pem"),
        ("OpenPGP ASCII Armor format (*.asc)", "asc"),
    ];
    let fmt_idx = Select::new()
        .with_prompt("Select key file format")
        .items(
            &format_options
                .iter()
                .map(|(display, _)| *display)
                .collect::<Vec<_>>(),
        )
        .default(0)
        .interact()?;
    let fmt = format_options[fmt_idx].1; // Get the internal name ("pem" or "asc")

    // --- Load Signer Keys ---
    let signer_priv_path: String = Input::<String>::new()
        .with_prompt("Signer PRIVATE key file path")
        .default(
            match fmt {
                "pem" => "keys/signer_private.pem", // Keep internal logic based on "pem" / "asc"
                _ => "keys/signer_private.asc",
            }
            .to_string(),
        )
        .interact_text()?;

    let (signer_public_key, signer_secret_key) = if fmt == "pem" {
        // Use internal name
        // PEM: Load public and private keys from separate files
        let signer_pub_path: String = Input::<String>::new()
            .with_prompt("Signer PUBLIC key file path")
            .default("keys/signer_public.pem".to_string())
            .interact_text()?;

        info!("Loading PKCS#8 signer keys..."); // Update log message
        let secret = load_secret_key(fmt, &signer_priv_path, None)?;
        let public = load_public_key(fmt, &signer_pub_path, None)?;
        (public, secret)
    } else {
        // "asc"
        // ASC: Load keypair from the private key file, prompt for password
        let password = Some(
            Password::new()
                .with_prompt("Signer private key password (if any)")
                .allow_empty_password(true) // Allow empty for unencrypted keys
                .interact()?,
        );

        info!("Loading OpenPGP signer keypair..."); // Update log message
                                                    // Use a helper or directly call load_keypair_from_pgp
        let keypair = load_keypair_from_pgp(&signer_priv_path, password.as_deref())
            .with_context(|| format!("Failed to load PGP keypair from '{}'", signer_priv_path))?;
        (keypair.public, keypair.secret)
    };

    // Verify modulus match
    if signer_public_key.n != signer_secret_key.n {
        return Err(anyhow!("Signer public and private key modulus mismatch!"));
    }
    info!("Signer keys loaded successfully.");

    // --- Load Member Public Keys ---
    let mut member_public_keys: Vec<PublicKey> = Vec::new();
    loop {
        let add_member = Confirm::new()
            .with_prompt(format!(
                "Add member public key #{}?",
                member_public_keys.len() + 1
            ))
            .default(true)
            .interact()?;

        if !add_member {
            break;
        }

        let member_pub_path: String = Input::<String>::new()
            .with_prompt(format!(
                "Member #{} PUBLIC key file path",
                member_public_keys.len() + 1
            ))
            .default(
                match fmt {
                    // Use internal name
                    "pem" => format!("keys/member{}_public.pem", member_public_keys.len() + 1),
                    _ => format!("keys/member{}_public.asc", member_public_keys.len() + 1),
                }
                .to_string(),
            )
            .interact_text()?;

        info!(
            "Loading member #{} public key...",
            member_public_keys.len() + 1
        );
        let member_pk = load_public_key(fmt, &member_pub_path, None)?;
        member_public_keys.push(member_pk);
        info!("Member key loaded.");
    }

    if member_public_keys.is_empty() {
        return Err(anyhow!(
            "At least one member public key is required besides the signer."
        ));
    }

    // --- Construct Ring ---
    // Signer is always index 0 in this CLI implementation
    let ring_pubs: Vec<PublicKey> = std::iter::once(signer_public_key.clone())
        .chain(member_public_keys.into_iter())
        .collect();
    let signer_index = 0;
    info!(
        "Ring constructed with {} members (including signer at index 0).",
        ring_pubs.len()
    );

    // --- Get Message ---
    let message_str: String = Input::<String>::new()
        .with_prompt("Enter the message to sign")
        .interact_text()?;
    let message = message_str.as_bytes();
    info!("Message to sign: {}", message_str);

    // --- Calculate Common Domain Bit Length 'b' ---
    let b = ring_pubs
        .iter()
        .map(|pk| pk.n.bits())
        .max()
        .unwrap_or(0) as usize // Should not happen with checks above
        + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

    if b == COMMON_DOMAIN_BIT_LENGTH_ADDITION {
        return Err(anyhow!("Failed to calculate common domain bit length 'b'. Ring might be empty or keys invalid."));
    }
    info!("Calculated common domain bit length b = {}", b);

    // --- Generate Ring Signature ---
    info!("Generating ring signature...");
    let ring_sig = ring_sign(&ring_pubs, signer_index, &signer_secret_key, message, b)
        .context("Failed to generate ring signature")?;
    info!("Ring signature generated successfully.");

    // --- Self-Verification (Optional but recommended) ---
    info!("Verifying generated signature...");
    let verify_result = ring_verify(&ring_pubs, &ring_sig, message, b)
        .context("Failed during self-verification")?;
    if !verify_result {
        error!("Self-verification FAILED! The generated signature is invalid.");
        return Err(anyhow!("Generated signature failed self-verification"));
    }
    info!("Self-verification successful.");

    // --- Prepare and Output JSON ---
    info!("Preparing JSON output...");
    let signature_payload = CliSignaturePayload {
        v: biguint_to_hex(&ring_sig.v),
        xs: ring_sig
            .xs
            .iter()
            .map(biguint_to_hex)
            .collect::<Vec<String>>(),
        message: message_str, // Store original message string
    };

    let json_output = serde_json::to_string_pretty(&signature_payload)
        .context("Failed to serialize signature to JSON")?;

    println!("\n--- Generated Signature (JSON) ---");
    println!("{}", json_output);
    println!("--- End of Signature ---");

    // --- Optionally Save to File ---
    let save_to_file = Confirm::new()
        .with_prompt("Save signature to a file?")
        .default(false)
        .interact()?;

    if save_to_file {
        let output_path: String = Input::<String>::new()
            .with_prompt("Enter output filename")
            .default("signature.json".to_string())
            .interact_text()?;

        info!("Saving signature to file: {}", output_path);
        fs::write(&output_path, &json_output)
            .with_context(|| format!("Failed to write signature to file '{}'", output_path))?;
        info!("Signature successfully saved to {}", output_path);
    }

    Ok(())
}

// --- Verify Mode ---
fn handle_verify() -> Result<()> {
    info!("--- Verify Mode ---");

    // --- Select Signature Input Method ---
    let input_methods = &["Read from file", "Paste from stdin"];
    let input_method_idx = Select::new()
        .with_prompt("How to provide the signature JSON?")
        .items(input_methods)
        .default(0)
        .interact()?;

    // --- Get Signature JSON Input ---
    let json_input_str = match input_methods[input_method_idx] {
        "Read from file" => {
            let input_path: String = Input::<String>::new()
                .with_prompt("Enter signature JSON file path")
                .default("signature.json".to_string())
                .validate_with(|input: &String| -> Result<(), &str> {
                    if Path::new(input).exists() {
                        Ok(())
                    } else {
                        Err("File does not exist")
                    }
                })
                .interact_text()?;
            info!("Reading signature from file: {}", input_path);
            fs::read_to_string(&input_path)
                .with_context(|| format!("Failed to read signature file '{}'", input_path))?
        }
        "Paste from stdin" => {
            println!("Paste the signature JSON below and press Ctrl+D (Unix) or Ctrl+Z then Enter (Windows) when done:");
            let mut buffer = String::new();
            stdin()
                .read_to_string(&mut buffer)
                .context("Failed to read signature JSON from stdin")?;
            buffer
        }
        _ => unreachable!(),
    };

    info!("Parsing signature JSON...");
    let signature_payload: CliSignaturePayload =
        serde_json::from_str(&json_input_str).context("Failed to parse signature JSON input")?;
    debug!("Parsed signature payload: {:?}", signature_payload);
    info!("Signature JSON parsed successfully.");

    // --- Select Key Format ---
    let format_options = &[
        ("PKCS#8 format (*.pem, *.key)", "pem"),
        ("OpenPGP ASCII Armor format (*.asc)", "asc"),
    ];
    let fmt_idx = Select::new()
        .with_prompt("Select key file format for ALL ring members")
        .items(
            &format_options
                .iter()
                .map(|(display, _)| *display)
                .collect::<Vec<_>>(),
        )
        .default(0)
        .interact()?;
    let fmt = format_options[fmt_idx].1; // Get the internal name ("pem" or "asc")

    // --- Load Public Keys (in order) ---
    let num_members = signature_payload.xs.len();
    if num_members == 0 {
        return Err(anyhow!(
            "Signature payload contains no members (xs is empty)."
        ));
    }
    info!("Signature indicates {} ring members. Please provide public keys in the original signing order.", num_members);

    let mut ring_pubs: Vec<PublicKey> = Vec::with_capacity(num_members);
    for i in 0..num_members {
        let pub_path: String = Input::<String>::new()
            .with_prompt(format!(
                "Member #{} PUBLIC key file path (original index {})",
                i + 1,
                i
            ))
            .default(
                match fmt {
                    // Use internal name
                    "pem" => format!("keys/member{}_public.pem", i), // Adjust default naming if needed
                    _ => format!("keys/member{}_public.asc", i),
                }
                .to_string(),
            )
            .interact_text()?;

        info!("Loading member #{} public key...", i + 1);
        let pk = load_public_key(fmt, &pub_path, None)?;
        ring_pubs.push(pk);
        info!("Member key loaded.");
    }

    // --- Reconstruct Ring Signature ---
    info!("Reconstructing signature data...");
    let v =
        hex_to_biguint(&signature_payload.v).context("Failed to convert signature 'v' from hex")?;
    let xs: Result<Vec<BigUint>> = signature_payload
        .xs
        .iter()
        .enumerate()
        .map(|(i, x_hex)| {
            hex_to_biguint(x_hex)
                .with_context(|| format!("Failed to convert signature 'xs[{}]' from hex", i))
        })
        .collect();
    let xs = xs?;

    if xs.len() != ring_pubs.len() {
        return Err(anyhow!(
            "Number of public keys provided ({}) does not match number of signature parts 'xs' ({})",
            ring_pubs.len(),
            xs.len()
        ));
    }

    let ring_sig = RingSignature { v, xs };
    let message = signature_payload.message.as_bytes();
    info!("Signature data reconstructed.");
    debug!("Reconstructed ring_sig: {:?}", ring_sig);
    debug!("Message bytes: {:?}", message);

    // --- Calculate Common Domain Bit Length 'b' ---
    let b = ring_pubs
        .iter()
        .map(|pk| pk.n.bits())
        .max()
        .unwrap_or(0) as usize // Should not happen with checks above
        + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

    if b == COMMON_DOMAIN_BIT_LENGTH_ADDITION {
        return Err(anyhow!(
            "Failed to calculate common domain bit length 'b' from provided keys."
        ));
    }
    info!("Calculated common domain bit length b = {}", b);

    // --- Verify Ring Signature ---
    info!("Verifying ring signature...");
    let verify_result = ring_verify(&ring_pubs, &ring_sig, message, b)
        .context("Failed during signature verification")?;

    println!("\n--- Verification Result ---");
    if verify_result {
        println!("Signature is VALID.");
        info!("Verification successful.");
    } else {
        println!("Signature is INVALID.");
        info!("Verification failed.");
    }
    println!("--- End of Verification ---");

    Ok(())
}

// --- Helper Functions for Key Loading ---

fn load_public_key(fmt: &str, path: &str, _password: Option<&str>) -> Result<PublicKey> {
    match fmt {
        "pem" => load_public_key_from_pem(path)
            .with_context(|| format!("Failed to load PEM public key from '{}'", path)),
        "asc" => load_public_key_from_pgp(path)
            .with_context(|| format!("Failed to load PGP public key from '{}'", path)),
        _ => Err(anyhow!("Unsupported key format: {}", fmt)),
    }
}

fn load_secret_key(fmt: &str, path: &str, password: Option<&str>) -> Result<SecretKey> {
    match fmt {
        "pem" => load_secret_key_from_pem(path)
            .with_context(|| format!("Failed to load PEM secret key from '{}'", path)),
        "asc" => {
            // PGP keypairs are loaded together, but we only need the secret part here.
            // We assume the public part was loaded separately or matches.
            let keypair = load_keypair_from_pgp(path, password)
                .with_context(|| format!("Failed to load PGP keypair from '{}'", path))?;
            Ok(keypair.secret)
        }
        _ => Err(anyhow!("Unsupported key format: {}", fmt)),
    }
}
