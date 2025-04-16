use anyhow::Result;
use num_traits::One;
use ring_signature::constants::COMMON_DOMAIN_BIT_LENGTH_ADDITION; // constants モジュールを使用
use ring_signature::ring::{ring_sign, ring_verify};
use ring_signature::rsa::{load_public_key_from_pem, load_secret_key_from_pem, KeyPair, PublicKey};
use ring_signature::rsa::{rsa_sign, rsa_verify};
use sha3::Digest;
use std::path::Path; // For path joining

fn main() -> Result<()> {
    env_logger::init();

    // Define paths to key files (adjust paths as needed)
    // Assumes a 'keys' directory in the project root or relative to execution
    let key_dir = Path::new("keys"); // Or specify an absolute path
    let signer_priv_key_path = key_dir.join("signer_private.pem");
    let signer_pub_key_path = key_dir.join("signer_public.pem");
    let member1_pub_key_path = key_dir.join("member1_public.pem");
    let member2_pub_key_path = key_dir.join("member2_public.pem");

    // --- Load Keys ---
    println!("Loading keys from PEM files...");
    let signer_secret_key = load_secret_key_from_pem(signer_priv_key_path.to_str().unwrap())?;
    let signer_public_key = load_public_key_from_pem(signer_pub_key_path.to_str().unwrap())?;
    let member1_public_key = load_public_key_from_pem(member1_pub_key_path.to_str().unwrap())?;
    let member2_public_key = load_public_key_from_pem(member2_pub_key_path.to_str().unwrap())?;

    // Create the ring of public keys (ensure signer's public key is included)
    let ring_pubs: Vec<PublicKey> = vec![
        signer_public_key.clone(), // Signer is index 0
        member1_public_key,
        member2_public_key,
    ];
    let signer_index = 0; // Assuming the key loaded into signer_secret_key corresponds to the first public key

    println!("Keys loaded successfully.");
    println!(
        "Signer public key n: ...{}...",
        &signer_public_key.n.to_string()[..20]
    ); // Print snippet
    println!(
        "Signer secret key n: ...{}...",
        &signer_secret_key.n.to_string()[..20]
    ); // Print snippet

    // Verify consistency (optional check)
    if signer_public_key.n != signer_secret_key.n {
        eprintln!("Error: Signer public and private key moduli do not match!");
        // return Err(anyhow::anyhow!("Signer key mismatch")); // Or handle appropriately
    }

    let message = b"Hello RSA and Ring Signature!";

    // --- Remove RSA Sign/Verify Example ---
    println!("Signing message with RSA...");
    // Calculate parameter 'b' for RSA: use the signer's public key modulus size plus the constant addition.
    let rsa_b = signer_public_key.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
    // Compute the hash of the message using SHA3-256 (ensure the 'sha3' crate is included in Cargo.toml)
    let hash = sha3::Sha3_256::digest(message);
    // Convert the hash to a BigUint and reduce it modulo 2^b (requires the 'num-bigint' and 'num-traits' crates)
    let m = num_bigint::BigUint::from_bytes_be(&hash) % (num_bigint::BigUint::one() << rsa_b);

    // Generate the RSA signature using the signer's key pair
    let signer_keypair = KeyPair {
        public: signer_public_key.clone(),
        secret: signer_secret_key.clone(),
    };
    let rsa_signature = rsa_sign(&signer_keypair, &m, rsa_b)?;
    println!(
        "RSA署名: {}",
        rsa_signature
            .to_bytes_be()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    println!("Verifying RSA signature...");
    // Verify the RSA signature using the signer's public key
    let rsa_verify_result = rsa_verify(&signer_public_key, &m, &rsa_signature, rsa_b)?;
    println!("通常RSA署名検証結果: {}", rsa_verify_result);

    // --- Ring Signature using Loaded Keys ---
    // Calculate b based on the maximum modulus size in the loaded ring
    let b = ring_pubs
        .iter()
        .map(|pk| pk.n.bits())
        .max()
        .unwrap_or(0) as usize // Handle empty ring case if necessary, though unlikely here
        + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

    if b == COMMON_DOMAIN_BIT_LENGTH_ADDITION {
        eprintln!("Error: Could not determine maximum key size from loaded keys.");
        return Err(anyhow::anyhow!("Failed to calculate b"));
    }

    println!("Generating ring signature...");
    let ring_sig = ring_sign(
        &ring_pubs,
        signer_index,       // Use the correct index for the signer
        &signer_secret_key, // Use the loaded secret key
        message,
        b,
    )?;
    println!(
        "リング署名 (v): {}", // Only show v for brevity, xs can be very long
        ring_sig
            .v
            .to_bytes_be()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    // println!(
    //     "リング署名の各メンバーのxの値: {}",
    //     ring_sig
    //         .xs
    //         .iter()
    //         .map(|x| format!("{:02x}", x)) // Consider limiting output size
    //         .collect::<Vec<String>>()
    //         .join(", ")
    // );
    // println!(
    //     "リング署名のグルー値v: {}",
    //     ring_sig
    //         .v
    //         .to_bytes_be()
    //         .iter()
    //         .map(|b| format!("{:02x}", b))
    //         .collect::<String>()
    // );

    println!("Verifying ring signature...");
    // let ring_pubs_verify: Vec<PublicKey> = keypair_vec.iter().map(|kp| kp.public.clone()).collect(); // Use loaded keys
    let ring_sig_verify_result = ring_verify(&ring_pubs, &ring_sig, message, b)?;

    println!("リング署名検証結果: {}", ring_sig_verify_result);
    Ok(())
}
