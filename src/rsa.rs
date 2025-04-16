use crate::constants;
use crate::error::RsaError;
use anyhow::Result;
use log::{debug, info, trace};
use num_bigint::BigUint;
use num_integer::Integer;
use num_prime::RandPrime;
use num_traits::{One, Zero};
use rand::Rng;
use rsa::{
    // pkcs1::DecodeRsaPrivateKey, // Removed PKCS#1 import for private key
    pkcs8::{DecodePrivateKey, DecodePublicKey}, // Added DecodePrivateKey for PKCS#8
    traits::{PrivateKeyParts, PublicKeyParts},
    RsaPrivateKey,
    RsaPublicKey,
};
use std::fs; // Added for file reading // Added for PEM parsing

// RSA公開鍵
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub n: BigUint, // モジュラス (公開鍵の法)
    pub e: BigUint, // 公開指数
}

// RSA秘密鍵
#[derive(Clone, Debug)]
pub struct SecretKey {
    pub d: BigUint, // 秘密指数
    pub n: BigUint, // モジュラス (公開鍵と共通)
}

// RSA鍵ペア (公開鍵と秘密鍵)
#[derive(Debug)]
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

/// 拡張RSAトラップドア関数 g
pub fn g(pubkey: &PublicKey, x: &BigUint, _b: usize) -> BigUint {
    // 内部不変条件: n > 0, e > 0
    assert!(!pubkey.n.is_zero(), "RSA公開鍵nが0です");
    assert!(!pubkey.e.is_zero(), "RSA公開鍵eが0です");
    trace!("g: pubkey = {:?}, x = {}, _b = {}", pubkey, x, _b);
    let (q, r) = x.div_rem(&pubkey.n);
    debug!("g: q = {}, r = {}", q, r);
    let r_exp = r.modpow(&pubkey.e, &pubkey.n);
    debug!("g: r_exp = {}", r_exp);
    let result = &q * &pubkey.n + r_exp;
    trace!("g: result = {}", result);
    result
}

/// 拡張RSAトラップドア関数の逆関数 g⁻¹
pub fn g_inverse(secret: &SecretKey, y: &BigUint, _b: usize) -> BigUint {
    // 内部不変条件: n > 0, d > 0
    assert!(!secret.n.is_zero(), "RSA秘密鍵nが0です");
    assert!(!secret.d.is_zero(), "RSA秘密鍵dが0です");
    trace!("g_inverse: secret = {:?}, y = {}, _b = {}", secret, y, _b);
    let (q, r) = y.div_rem(&secret.n);
    debug!("g_inverse: q = {}, r = {}", q, r);
    let r_dec = r.modpow(&secret.d, &secret.n);
    debug!("g_inverse: r_dec = {}", r_dec);
    let result = &q * &secret.n + r_dec;
    trace!("g_inverse: result = {}", result);
    result
}

/// RSA署名生成
pub fn rsa_sign(key: &KeyPair, m: &BigUint, b: usize) -> Result<BigUint> {
    info!("RSA署名生成開始: key = {:?}, m = {}, b = {}", key, m, b);
    // g_inverseは失敗しない前提だが、将来的な拡張のためResult型に
    let signature = g_inverse(&key.secret, m, b);
    info!("RSA署名生成完了: signature = {}", signature);
    Ok(signature)
}

/// RSA署名検証
pub fn rsa_verify(pubkey: &PublicKey, m: &BigUint, signature: &BigUint, b: usize) -> Result<bool> {
    info!(
        "RSA署名検証開始: pubkey = {:?}, m = {}, signature = {}, b = {}",
        pubkey, m, signature, b
    );
    let verification = g(pubkey, signature, b) == *m;
    info!("RSA署名検証結果: {}", verification);
    Ok(verification)
}

/// RSA鍵ペア生成
pub fn generate_keypair(bits: usize, rng: &mut impl Rng) -> Result<KeyPair> {
    info!("RSA鍵ペア生成開始: bits = {}", bits);
    let p: BigUint = rng.gen_prime_exact(bits / 2, None);
    let q: BigUint = rng.gen_prime_exact(bits / 2, None);
    debug!("generate_keypair: p = {}, q = {}", p, q);

    let n = &p * &q;
    debug!("generate_keypair: n = {}", n);

    let phi = (&p - BigUint::one()) * (&q - BigUint::one());
    debug!("generate_keypair: phi = {}", phi);

    let e = BigUint::from(constants::E);

    let d = match e.modinv(&phi) {
        Some(val) => val,
        None => return Err(RsaError::NotCoprime.into()),
    };
    debug!("generate_keypair: d = {}", d);

    let keypair = KeyPair {
        public: PublicKey {
            n: n.clone(),
            e: e.clone(),
        },
        secret: SecretKey { d, n },
    };
    info!("RSA鍵ペア生成完了: keypair = {:?}", keypair);
    Ok(keypair)
}

/// Load RSA Public Key from PEM file (SPKI format)
pub fn load_public_key_from_pem(filepath: &str) -> Result<PublicKey> {
    info!("Loading public key from PEM: {}", filepath);
    let pem_str = fs::read_to_string(filepath)?;
    // Try parsing as PKCS#1 first, then SPKI if needed, though SPKI is more standard for public keys.
    // RsaPublicKey::from_public_key_pem expects SPKI format.
    // If your key is in PKCS#1 public key format, you might need from_pkcs1_pem.
    // Let's assume SPKI format for public keys as it's common.
    // If PKCS#1 public key format is used, use RsaPublicKey::from_pkcs1_pem(&pem_str)?
    let rsa_pub_key = RsaPublicKey::from_public_key_pem(&pem_str)
        .map_err(|e| RsaError::Other(format!("Failed to parse public key PEM: {}", e)))?;

    let n = BigUint::from_bytes_be(rsa_pub_key.n().to_bytes_be().as_slice());
    let e = BigUint::from_bytes_be(rsa_pub_key.e().to_bytes_be().as_slice());
    info!(
        "Public key loaded successfully: n bits = {}, e = {}",
        n.bits(),
        e
    );
    Ok(PublicKey { n, e })
}

/// Load RSA Secret Key from PEM file (PKCS#8 format)
pub fn load_secret_key_from_pem(filepath: &str) -> Result<SecretKey> {
    info!("Loading secret key from PEM: {}", filepath);
    let pem_str = fs::read_to_string(filepath)?;
    // Assuming PKCS#8 format for private keys.
    let rsa_priv_key = RsaPrivateKey::from_pkcs8_pem(&pem_str)
        .map_err(|e| RsaError::Other(format!("Failed to parse private key PEM (PKCS#8): {}", e)))?;

    let n = BigUint::from_bytes_be(rsa_priv_key.n().to_bytes_be().as_slice());
    let d = BigUint::from_bytes_be(rsa_priv_key.d().to_bytes_be().as_slice());
    info!("Secret key loaded successfully: n bits = {}", n.bits());
    Ok(SecretKey { d, n })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::COMMON_DOMAIN_BIT_LENGTH_ADDITION;
    use num_bigint::RandBigInt;
    use num_prime::nt_funcs::is_prime;
    use num_traits::{One, Zero};
    use rand::thread_rng;
    use sha3::Digest;
    use sha3::Sha3_256;

    const TEST_RSA_BITS: usize = 2048; // Use 2048 bits for tests

    #[test]
    fn test_rsa_sign_success() {
        let mut rng = thread_rng();
        let rsa_bits = TEST_RSA_BITS; // Use constant
        let keypair = generate_keypair(rsa_bits, &mut rng).unwrap();
        let b = keypair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let message = b"Test message";
        let hash = Sha3_256::digest(message);
        let m = BigUint::from_bytes_be(&hash) % (BigUint::one() << b);
        let signature = rsa_sign(&keypair, &m, b).unwrap();
        assert!(rsa_verify(&keypair.public, &m, &signature, b).unwrap());
    }

    #[test]
    fn test_rsa_sign_fail() {
        let mut rng = thread_rng();
        let rsa_bits = TEST_RSA_BITS; // Use constant
        let keypair = generate_keypair(rsa_bits, &mut rng).unwrap();
        let b = keypair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let message = b"Test message";
        let hash = Sha3_256::digest(message);
        let m = BigUint::from_bytes_be(&hash) % (BigUint::one() << b);
        let signature = rsa_sign(&keypair, &m, b).unwrap();
        let wrong_message = b"Wrong message";
        let wrong_hash = Sha3_256::digest(wrong_message);
        let wrong_m = BigUint::from_bytes_be(&wrong_hash) % (BigUint::one() << b);
        assert!(!rsa_verify(&keypair.public, &wrong_m, &signature, b).unwrap());
    }

    #[test]
    fn test_g_inverse() {
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS; // Use constant
        let key_pair = generate_keypair(bits, &mut rng).unwrap(); //鍵ペアを作成
        let b = key_pair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

        // いくつかのランダムな値でテスト
        for _ in 0..10 {
            let x = rng.gen_biguint(b as u64); // ランダムな値を生成
            let y = g(&key_pair.public, &x, b); // g 関数を適用
            let x_prime = g_inverse(&key_pair.secret, &y, b); // 逆関数を適用
            assert_eq!(x, x_prime); // 元の値と一致することを確認
        }
        // Zeroでのテスト
        let x = BigUint::zero();
        let y = g(&key_pair.public, &x, b);
        let x_prime = g_inverse(&key_pair.secret, &y, b);
        assert_eq!(x, x_prime); //0の場合
    }

    #[test]
    fn test_g_inverse_near_n() {
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS; // Use constant
        let key_pair = generate_keypair(bits, &mut rng).unwrap();
        let b = key_pair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

        // n - 1 でテスト
        let y = &key_pair.public.n - BigUint::one();
        let x = g_inverse(&key_pair.secret, &y, b);
        let expected_x = (&y / &key_pair.secret.n) * &key_pair.secret.n
            + y.modpow(&key_pair.secret.d, &key_pair.secret.n);
        assert_eq!(x, expected_x, "g_inverse が n-1 で正しく動作しない");
    }

    #[test]
    fn test_g_inverse_multiple_of_n() {
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS; // Use constant
        let key_pair = generate_keypair(bits, &mut rng).unwrap();
        let b = key_pair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

        // 2*n でテスト
        let y = &key_pair.public.n * BigUint::from(2u32);
        let x = g_inverse(&key_pair.secret, &y, b);
        let expected_x = (&y / &key_pair.secret.n) * &key_pair.secret.n
            + y.modpow(&key_pair.secret.d, &key_pair.secret.n);

        assert_eq!(x, expected_x, "g_inverse が 2*n で正しく動作しない");
    }

    #[test]
    fn test_g_success() {
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS; // Use constant
        let key_pair = generate_keypair(bits, &mut rng).unwrap();
        let b = key_pair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let x = rng.gen_biguint(b as u64);

        let y = g(&key_pair.public, &x, b);

        // g(x) = q*n + r^e mod n を検証
        let (q, r) = x.div_rem(&key_pair.public.n);
        let r_exp = r.modpow(&key_pair.public.e, &key_pair.public.n);
        let expected_y = &q * &key_pair.public.n + r_exp;

        assert_eq!(y, expected_y);
    }

    // g 関数のテスト（ゼロでのケース）
    #[test]
    fn test_g_zero() {
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS; // Use constant
        let key_pair = generate_keypair(bits, &mut rng).unwrap();
        let b = key_pair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let x = BigUint::zero();

        let y = g(&key_pair.public, &x, b);

        // x が 0 の場合、g(x) は 0^e mod n = 0 となるはず
        assert_eq!(y, BigUint::zero());
    }

    // g_inverse 関数のテスト（成功ケース）
    #[test]
    fn test_g_inverse_success() {
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS; // Use constant
        let key_pair = generate_keypair(bits, &mut rng).unwrap();
        let b = key_pair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let y = rng.gen_biguint(b as u64);

        let x = g_inverse(&key_pair.secret, &y, b);

        // g_inverse(y) = q*n + r^d mod n を検証
        let (q, r) = y.div_rem(&key_pair.secret.n);
        let r_dec = r.modpow(&key_pair.secret.d, &key_pair.secret.n);
        let expected_x = &q * &key_pair.secret.n + r_dec;

        assert_eq!(x, expected_x);
    }

    // g_inverse 関数のテスト（ゼロでのケース）
    #[test]
    fn test_g_inverse_zero() {
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS; // Use constant
        let key_pair = generate_keypair(bits, &mut rng).unwrap();
        let b = key_pair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let y = BigUint::zero();

        let x = g_inverse(&key_pair.secret, &y, b);
        // y が 0 の場合、g_inverse(y) は 0^d mod n = 0 となるはず
        assert_eq!(x, BigUint::zero());
    }

    // gen_prime 関数のテスト
    #[test]
    fn test_gen_prime() {
        let mut rng = thread_rng();
        let bits = 128;
        let prime: BigUint = rng.gen_prime_exact(bits, None);
        // 生成された数が指定されたビット長であること
        assert_eq!(prime.bits(), bits as u64);
        // 生成された数が素数であること
        assert!(is_prime(&prime, None).probably());
    }

    // modinv 関数のテスト（成功ケース）
    #[test]
    fn test_modinv_success() {
        let a = BigUint::from(3u32);
        let m = BigUint::from(11u32);
        let inv = a.modinv(&m);
        // 3 * 4 mod 11 = 1 なので、逆元は 4
        assert_eq!(inv, Some(BigUint::from(4u32)));
    }

    // modinv 関数のテスト（逆元が存在しないケース）
    #[test]
    fn test_modinv_none() {
        let a = BigUint::from(4u32);
        let m = BigUint::from(12u32); // gcd(4, 12) = 4 != 1
        let inv = a.modinv(&m);
        // 逆元は存在しない
        assert_eq!(inv, None);
    }

    // Example of how a test *could* look (requires creating test key files)
    /*
    #[test]
    fn test_load_keys_from_pem() -> Result<()> {
        // Create dummy PEM files for testing purposes in a 'test_keys' directory
        // For example: test_keys/test_pub.pem, test_keys/test_priv.pem
        // Ensure these files exist before running the test.
        let test_pub_path = "test_keys/test_pub.pem";
        let test_priv_path = "test_keys/test_priv.pem";

        // Create the directory if it doesn't exist
        fs::create_dir_all("test_keys").expect("Failed to create test_keys directory");

        // Generate a keypair and save it to PEM files for the test
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS; // Use constant // Use a smaller size for faster test generation
        let keypair = generate_keypair(bits, &mut rng)?;
        let priv_pem = keypair.secret.to_pkcs1_pem(Default::default())?; // Assuming SecretKey can be converted back easily or using the 'rsa' crate's types directly
        let pub_pem = keypair.public.to_public_key_pem(Default::default())?; // Assuming PublicKey can be converted back easily
        fs::write(test_priv_path, priv_pem)?;
        fs::write(test_pub_path, pub_pem)?;


        let public_key = load_public_key_from_pem(test_pub_path)?;
        let secret_key = load_secret_key_from_pem(test_priv_path)?;

        assert_eq!(public_key.n, secret_key.n);
        // Add more assertions if needed, e.g., comparing with original generated values

        // Clean up test files
        fs::remove_file(test_pub_path)?;
        fs::remove_file(test_priv_path)?;
        fs::remove_dir("test_keys")?;


        Ok(())
    }
    */
}
