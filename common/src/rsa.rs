use crate::constants;
use crate::error::RsaError;
use anyhow::{anyhow, Result};
use log::{debug, info, trace};
use num_bigint::BigUint;
use num_integer::Integer;
use num_prime::RandPrime;
use num_traits::{One, Zero};
use rand::Rng;
// PKCS#8形式の秘密鍵と公開鍵をデコードするためのトレイト
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    traits::{PrivateKeyParts, PublicKeyParts},
    RsaPrivateKey, RsaPublicKey,
};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::{cert::Cert, policy::StandardPolicy};
use sequoia_openpgp::{
    crypto::{mpi::PublicKey as OpenPgpPublicKey, Password},
    packet::{key::SecretKeyMaterial, Key},
};
use std::io::Read;
use std::{
    fs::{self, File},
    io::BufReader,
};

// RSA公開鍵を表す構造体
#[derive(Clone, Debug)]
pub struct PublicKey {
    // モジュラス (法)
    pub n: BigUint,
    // 公開指数
    pub e: BigUint,
}

// RSA秘密鍵を表す構造体
#[derive(Clone, Debug)]
pub struct SecretKey {
    // 秘密指数
    pub d: BigUint,
    // モジュラス (公開鍵と共通)
    pub n: BigUint,
}

// RSA鍵ペア (公開鍵と秘密鍵) を表す構造体
#[derive(Debug)]
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

/// 拡張RSAトラップドア関数 g(x) = q*n + r^e mod n
/// x: 入力値
/// b: 共通ドメインのビット長
pub fn g(pubkey: &PublicKey, x: &BigUint, _b: usize) -> BigUint {
    // 内部不変条件: n > 0, e > 0
    assert!(!pubkey.n.is_zero(), "RSA公開鍵nが0です");
    assert!(!pubkey.e.is_zero(), "RSA公開鍵eが0です");
    trace!("g: pubkey = {:?}, x = {}, _b = {}", pubkey, x, _b);
    // x を n で割った商 q と剰余 r を計算
    let (q, r) = x.div_rem(&pubkey.n);
    debug!("g: q = {}, r = {}", q, r);
    // 剰余 r を公開指数 e でべき乗し、n で剰余を取る (r^e mod n)
    let r_exp = r.modpow(&pubkey.e, &pubkey.n);
    debug!("g: r_exp = {}", r_exp);
    // 結果 q*n + (r^e mod n) を計算
    let result = &q * &pubkey.n + r_exp;
    trace!("g: result = {}", result);
    result
}

/// 拡張RSAトラップドア関数の逆関数 g⁻¹(y) = q*n + r^d mod n
/// y: 入力値
/// b: 共通ドメインのビット長
pub fn g_inverse(secret: &SecretKey, y: &BigUint, _b: usize) -> BigUint {
    // 内部不変条件: n > 0, d > 0
    assert!(!secret.n.is_zero(), "RSA秘密鍵nが0です");
    assert!(!secret.d.is_zero(), "RSA秘密鍵dが0です");
    trace!("g_inverse: secret = {:?}, y = {}, _b = {}", secret, y, _b);
    // y を n で割った商 q と剰余 r を計算
    let (q, r) = y.div_rem(&secret.n);
    debug!("g_inverse: q = {}, r = {}", q, r);
    // 剰余 r を秘密指数 d でべき乗し、n で剰余を取る (r^d mod n)
    let r_dec = r.modpow(&secret.d, &secret.n);
    debug!("g_inverse: r_dec = {}", r_dec);
    // 結果 q*n + (r^d mod n) を計算
    let result = &q * &secret.n + r_dec;
    trace!("g_inverse: result = {}", result);
    result
}

/// RSA署名生成 (g関数の逆関数を利用)
/// key: 署名者の鍵ペア
/// m: 署名対象のメッセージ (ハッシュ化・パディング済み)
/// b: 共通ドメインのビット長
pub fn rsa_sign(key: &KeyPair, m: &BigUint, b: usize) -> Result<BigUint> {
    // infoには主要パラメータのみ、詳細はdebugで出力
    info!(
        "RSA署名生成開始: key.n bits = {}, m bits = {}, b = {}",
        key.public.n.bits(),
        m.bits(),
        b
    );
    debug!("RSA署名生成開始: key = {:?}, m = {}", key, m);
    // g_inverseは失敗しない前提だが、将来的な拡張のためResult型に
    // 秘密鍵を用いて g 関数の逆関数を計算し、署名とする
    let signature = g_inverse(&key.secret, m, b);
    // infoにはビット数のみ表示し、内容はdebugで出力
    info!("RSA署名生成完了: {} bits", signature.bits());
    debug!("RSA署名生成完了: signature = {}", signature);
    Ok(signature)
}

/// RSA署名検証 (g関数を利用)
/// pubkey: 署名者の公開鍵
/// m: 検証対象のメッセージ (ハッシュ化・パディング済み)
/// signature: 検証対象の署名
/// b: 共通ドメインのビット長
pub fn rsa_verify(pubkey: &PublicKey, m: &BigUint, signature: &BigUint, b: usize) -> Result<bool> {
    // infoには主要パラメータのみ、詳細はdebugで出力
    info!(
        "RSA署名検証開始: pubkey.n bits = {}, m bits = {}, signature bits = {}, b = {}",
        pubkey.n.bits(),
        m.bits(),
        signature.bits(),
        b
    );
    debug!(
        "RSA署名検証開始: pubkey = {:?}, m = {}, signature = {}",
        pubkey, m, signature
    );
    // 公開鍵を用いて g 関数を署名に適用し、元のメッセージ m と一致するか検証
    let verification = g(pubkey, signature, b) == *m;
    info!("RSA署名検証結果: {}", verification);
    Ok(verification)
}

/// RSA鍵ペア生成
/// bits: 生成する鍵のビット長 (素数p, qのビット長の合計)
/// rng: 乱数生成器
pub fn generate_keypair(bits: usize, rng: &mut impl Rng) -> Result<KeyPair> {
    info!("RSA鍵ペア生成開始: bits = {}", bits);
    // 指定されたビット長の半分を持つ素数 p を生成
    let p: BigUint = rng.gen_prime_exact(bits / 2, None);
    // 指定されたビット長の半分を持つ素数 q を生成
    let q: BigUint = rng.gen_prime_exact(bits / 2, None);
    debug!("generate_keypair: p = {}, q = {}", p, q);

    // モジュラス n = p * q を計算
    let n = &p * &q;
    debug!("generate_keypair: n = {}", n);

    // オイラーのトーシェント関数 φ(n) = (p-1)*(q-1) を計算
    let phi = (&p - BigUint::one()) * (&q - BigUint::one());
    debug!("generate_keypair: phi = {}", phi);

    // 公開指数 e を定数から取得
    let e = BigUint::from(constants::E);

    // e と φ(n) のモジュラ逆数 d を計算 (秘密指数)
    let d = match e.modinv(&phi) {
        Some(val) => val,
        // e と φ(n) が互いに素でない場合、エラー
        None => return Err(RsaError::NotCoprime.into()),
    };
    debug!("generate_keypair: d = {}", d);

    // 生成した公開鍵と秘密鍵から鍵ペアを作成
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

/// PEMファイル (SPKI形式) からRSA公開鍵を読み込む
/// filepath: PEMファイルのパス
pub fn load_public_key_from_pem(filepath: &str) -> Result<PublicKey> {
    info!("Loading public key from PEM: {}", filepath);
    // PEMファイルを文字列として読み込む
    let pem_str = fs::read_to_string(filepath)?;
    // SPKI形式のPEM文字列から RsaPublicKey をデコード
    let rsa_pub_key = RsaPublicKey::from_public_key_pem(&pem_str)
        .map_err(|e| RsaError::Other(format!("Failed to parse public key PEM: {}", e)))?;

    // RsaPublicKey から n と e を BigUint 型に変換
    let n = BigUint::from_bytes_be(rsa_pub_key.n().to_bytes_be().as_slice());
    let e = BigUint::from_bytes_be(rsa_pub_key.e().to_bytes_be().as_slice());
    info!(
        "Public key loaded successfully: n bits = {}, e = {}",
        n.bits(),
        e
    );
    // PublicKey 構造体を作成して返す
    Ok(PublicKey { n, e })
}

/// PEMファイル (PKCS#8形式) からRSA秘密鍵を読み込む
/// filepath: PEMファイルのパス
pub fn load_secret_key_from_pem(filepath: &str) -> Result<SecretKey> {
    info!("Loading secret key from PEM: {}", filepath);
    // PEMファイルを文字列として読み込む
    let pem_str = fs::read_to_string(filepath)?;
    // PKCS#8形式のPEM文字列から RsaPrivateKey をデコード
    let rsa_priv_key = RsaPrivateKey::from_pkcs8_pem(&pem_str)
        .map_err(|e| RsaError::Other(format!("Failed to parse private key PEM (PKCS#8): {}", e)))?;

    // RsaPrivateKey から n と d を BigUint 型に変換
    let n = BigUint::from_bytes_be(rsa_priv_key.n().to_bytes_be().as_slice());
    let d = BigUint::from_bytes_be(rsa_priv_key.d().to_bytes_be().as_slice());
    info!("Secret key loaded successfully: n bits = {}", n.bits());
    // SecretKey 構造体を作成して返す
    Ok(SecretKey { d, n })
}

pub fn load_public_key_from_pgp(filepath: &str) -> Result<PublicKey> {
    // Read the PGP certificate file
    let mut file = File::open(filepath)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    // Parse the certificate
    let cert = Cert::from_bytes(&buf)?;

    // Define the policy
    let policy = &StandardPolicy::new();

    // Iterate over the keys in the certificate
    let key = cert
        .keys()
        .with_policy(policy, None)
        .alive()
        .for_signing() // Filter for signing-capable keys
        .next()
        .ok_or_else(|| anyhow::anyhow!("No valid signing-capable public key found"))?;

    // Extract the key material
    let key = key.key();

    // Match on the key material to extract RSA parameters
    if let OpenPgpPublicKey::RSA { ref e, ref n } = key.mpis() {
        Ok(PublicKey {
            n: BigUint::from_bytes_be(n.value()),
            e: BigUint::from_bytes_be(e.value()),
        })
    } else {
        Err(anyhow::anyhow!("Not an RSA public key"))
    }
}

/// RSA鍵ペアをファイルから読み込む。パスワードが必要なら `Some(password)` を渡す。
pub fn load_keypair(path: &str, password: Option<&str>) -> Result<KeyPair> {
    // ファイル読み込み → Cert 構築
    let reader = BufReader::new(File::open(path)?);
    let cert = Cert::from_reader(reader)?;

    // 秘密鍵を含む最初のキーを取得
    let binding = cert
        .keys()
        .secret() // 秘密鍵のみフィルタ :contentReference[oaicite:13]{index=13}
        .nth(0)
        .ok_or_else(|| anyhow!("Secret key not found"))?;
    let mut key = binding.key().clone();

    // 暗号化されているなら復号
    if key.has_secret() && !key.has_unencrypted_secret() {
        let pw = Password::from(password.unwrap_or(""));
        key = key.decrypt_secret(&pw)?; // :contentReference[oaicite:14]{index=14}
    }

    // SecretKeyMaterial から d, p, q を抽出
    if let Key::V4(key4) = key {
        if let SecretKeyMaterial::Unencrypted(m) = key4.secret() {
            m.map(|f| {
                if let sequoia_openpgp::crypto::mpi::SecretKeyMaterial::RSA { d, p, q, .. } = f {
                    // 各 MPI を BigUint に変換
                    let d = BigUint::from_bytes_be(d.value()); // :contentReference[oaicite:15]{index=15}
                    let p = BigUint::from_bytes_be(p.value()); // :contentReference[oaicite:16]{index=16}
                    let q = BigUint::from_bytes_be(q.value()); // :contentReference[oaicite:17]{index=17}

                    // n = p * q
                    let n = &p * &q;

                    // 公開指数は通常固定 (65537) だが、公開鍵 MPI から取得しても良い
                    let public = PublicKey {
                        n: n.clone(),
                        e: BigUint::from(65537u32),
                    };
                    let secret = SecretKey { n, d };
                }
            })
        } else {
            return Err(anyhow!("Not an RSA key"));
        }
    }

    Err(anyhow!("Not an RSA key"))
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

    // テストで使用するRSA鍵のビット長
    const TEST_RSA_BITS: usize = 2048;

    // RSA署名と検証が成功するかのテスト
    #[test]
    fn test_rsa_sign_success() {
        let mut rng = thread_rng();
        let rsa_bits = TEST_RSA_BITS;
        // 鍵ペア生成
        let keypair = generate_keypair(rsa_bits, &mut rng).unwrap();
        // 共通ドメインのビット長 b を計算
        let b = keypair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let message = b"Test message";
        // メッセージのハッシュ値を計算
        let hash = Sha3_256::digest(message);
        // ハッシュ値を BigUint に変換し、2^b で剰余を取る
        let m = BigUint::from_bytes_be(&hash) % (BigUint::one() << b);
        // RSA署名生成
        let signature = rsa_sign(&keypair, &m, b).unwrap();
        // RSA署名検証
        assert!(rsa_verify(&keypair.public, &m, &signature, b).unwrap());
    }

    // RSA署名検証が異なるメッセージで失敗するかのテスト
    #[test]
    fn test_rsa_sign_fail() {
        let mut rng = thread_rng();
        let rsa_bits = TEST_RSA_BITS;
        let keypair = generate_keypair(rsa_bits, &mut rng).unwrap();
        let b = keypair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let message = b"Test message";
        let hash = Sha3_256::digest(message);
        let m = BigUint::from_bytes_be(&hash) % (BigUint::one() << b);
        let signature = rsa_sign(&keypair, &m, b).unwrap();
        // 異なるメッセージで検証
        let wrong_message = b"Wrong message";
        let wrong_hash = Sha3_256::digest(wrong_message);
        let wrong_m = BigUint::from_bytes_be(&wrong_hash) % (BigUint::one() << b);
        // 検証が失敗することを確認
        assert!(!rsa_verify(&keypair.public, &wrong_m, &signature, b).unwrap());
    }

    // g関数の逆関数 g_inverse が g 関数の逆操作として正しく機能するかのテスト
    #[test]
    fn test_g_inverse() {
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS;
        let key_pair = generate_keypair(bits, &mut rng).unwrap();
        let b = key_pair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

        // ランダムな値でテスト
        for _ in 0..10 {
            let x = rng.gen_biguint(b as u64);
            // g(x) を計算
            let y = g(&key_pair.public, &x, b);
            // g_inverse(y) を計算
            let x_prime = g_inverse(&key_pair.secret, &y, b);
            // 元の x と一致するか確認
            assert_eq!(x, x_prime);
        }
        // 0 でテスト
        let x = BigUint::zero();
        let y = g(&key_pair.public, &x, b);
        let x_prime = g_inverse(&key_pair.secret, &y, b);
        assert_eq!(x, x_prime);
    }

    // g_inverse 関数が n に近い値 (n-1) で正しく動作するかのテスト
    #[test]
    fn test_g_inverse_near_n() {
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS;
        let key_pair = generate_keypair(bits, &mut rng).unwrap();
        let b = key_pair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

        // n - 1 でテスト
        let y = &key_pair.public.n - BigUint::one();
        let x = g_inverse(&key_pair.secret, &y, b);
        // 期待される計算結果
        let expected_x = (&y / &key_pair.secret.n) * &key_pair.secret.n
            + y.modpow(&key_pair.secret.d, &key_pair.secret.n);
        assert_eq!(x, expected_x, "g_inverse が n-1 で正しく動作しない");
    }

    // g_inverse 関数が n の倍数 (2*n) で正しく動作するかのテスト
    #[test]
    fn test_g_inverse_multiple_of_n() {
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS;
        let key_pair = generate_keypair(bits, &mut rng).unwrap();
        let b = key_pair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

        // 2*n でテスト
        let y = &key_pair.public.n * BigUint::from(2u32);
        let x = g_inverse(&key_pair.secret, &y, b);
        // 期待される計算結果
        let expected_x = (&y / &key_pair.secret.n) * &key_pair.secret.n
            + y.modpow(&key_pair.secret.d, &key_pair.secret.n);

        assert_eq!(x, expected_x, "g_inverse が 2*n で正しく動作しない");
    }

    // g 関数が正しく計算されるかのテスト
    #[test]
    fn test_g_success() {
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS;
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

    // g 関数が入力 0 で正しく動作するかのテスト
    #[test]
    fn test_g_zero() {
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS;
        let key_pair = generate_keypair(bits, &mut rng).unwrap();
        let b = key_pair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let x = BigUint::zero();

        let y = g(&key_pair.public, &x, b);

        // x が 0 の場合、g(x) は 0^e mod n = 0 となるはず
        assert_eq!(y, BigUint::zero());
    }

    // g_inverse 関数が正しく計算されるかのテスト
    #[test]
    fn test_g_inverse_success() {
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS;
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

    // g_inverse 関数が入力 0 で正しく動作するかのテスト
    #[test]
    fn test_g_inverse_zero() {
        let mut rng = thread_rng();
        let bits = TEST_RSA_BITS;
        let key_pair = generate_keypair(bits, &mut rng).unwrap();
        let b = key_pair.public.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let y = BigUint::zero();

        let x = g_inverse(&key_pair.secret, &y, b);
        // y が 0 の場合、g_inverse(y) は 0^d mod n = 0 となるはず
        assert_eq!(x, BigUint::zero());
    }

    // 素数生成関数 gen_prime_exact のテスト
    #[test]
    fn test_gen_prime() {
        let mut rng = thread_rng();
        let bits = 128;
        let prime: BigUint = rng.gen_prime_exact(bits, None);
        // 生成された数が指定されたビット長であること
        assert_eq!(prime.bits(), bits as u64);
        // 生成された数が素数であること (確率的素数判定)
        assert!(is_prime(&prime, None).probably());
    }

    // モジュラ逆数関数 modinv が正しく計算されるかのテスト (逆元が存在する場合)
    #[test]
    fn test_modinv_success() {
        let a = BigUint::from(3u32);
        let m = BigUint::from(11u32);
        let inv = a.modinv(&m);
        // 3 * 4 mod 11 = 1 なので、逆元は 4
        assert_eq!(inv, Some(BigUint::from(4u32)));
    }

    // モジュラ逆数関数 modinv が正しく計算されるかのテスト (逆元が存在しない場合)
    #[test]
    fn test_modinv_none() {
        let a = BigUint::from(4u32);
        let m = BigUint::from(12u32); // gcd(4, 12) = 4 != 1
        let inv = a.modinv(&m);
        // 逆元は存在しない
        assert_eq!(inv, None);
    }

    // PEMファイルからの鍵読み込みテスト (コメントアウトされているため変更なし)
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
