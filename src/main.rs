use anyhow::Result;
use num_bigint::BigUint;
use num_traits::One;
use rand::thread_rng;
use ring_signature::constants::COMMON_DOMAIN_BIT_LENGTH_ADDITION; // constants モジュールを使用
use ring_signature::ring::{ring_sign, ring_verify};
use ring_signature::rsa::{generate_keypair, rsa_sign, rsa_verify, PublicKey};
use sha3::{Digest, Sha3_256};

fn main() -> Result<()> {
    env_logger::init();

    let mut rng = thread_rng();

    let rsa_bits = 512;
    let keypair_vec: Vec<_> = (0..3)
        .map(|_| generate_keypair(rsa_bits, &mut rng))
        .collect::<Result<_>>()?;

    for (i, keypair) in keypair_vec.iter().enumerate() {
        println!("鍵ペア {}: {:?}", i, keypair);
    }

    let message = b"Hello RSA and Ring Signature!";

    let b = keypair_vec[0].public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
    let hash = Sha3_256::digest(message);
    let m = BigUint::from_bytes_be(&hash) % (BigUint::one() << b);

    let signature = rsa_sign(&keypair_vec[0], &m, b)?;
    println!(
        "署名: {}",
        signature
            .to_bytes_be()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    let rsa_verify_result = rsa_verify(&keypair_vec[0].public, &m, &signature, b)?;
    println!("通常RSA署名検証結果: {}", rsa_verify_result);

    let b = keypair_vec
        .iter()
        .map(|kp| kp.public.n.bits())
        .max()
        .unwrap() as usize
        + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

    let ring_sig = ring_sign(
        &keypair_vec
            .iter()
            .map(|kp| kp.public.clone())
            .collect::<Vec<PublicKey>>()
            .as_slice(),
        0,
        &keypair_vec[0].secret,
        message,
        b,
    )?;
    println!(
        "リング署名: {}",
        ring_sig
            .v
            .to_bytes_be()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!(
        "リング署名の各メンバーのxの値: {}",
        ring_sig
            .xs
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<Vec<String>>()
            .join(", ")
    );
    println!(
        "リング署名のグルー値v: {}",
        ring_sig
            .v
            .to_bytes_be()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    let ring_pubs: Vec<PublicKey> = keypair_vec.iter().map(|kp| kp.public.clone()).collect();
    let ring_sig_verify_result = ring_verify(&ring_pubs, &ring_sig, message, b)?;

    println!("リング署名検証結果: {}", ring_sig_verify_result);
    Ok(())
}
