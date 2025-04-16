use crate::crypto_utils::{d_k, e_k};
use crate::error::RingError;
use crate::rsa::{g, g_inverse, PublicKey, SecretKey};
use anyhow::Result;
use log::{debug, error, info};
use num_bigint::{BigUint, RandBigInt};
use num_traits::Zero;
use rand::thread_rng;
use sha3::{Digest, Sha3_256};
use std::vec::Vec;

// リング署名
#[derive(Debug)]
pub struct RingSignature {
    pub v: BigUint,       // グルー値
    pub xs: Vec<BigUint>, // 各メンバーの寄与
}

/// リング署名生成（引数として公開鍵のリストと署名者のみの秘密鍵を受け取る）
pub fn ring_sign(
    ring: &[PublicKey],
    signer: usize,
    signer_secret: &SecretKey,
    m: &[u8],
    b: usize,
) -> Result<RingSignature> {
    info!(
        "リング署名生成開始: ring_size = {}, signer = {}, m = {:?}, b = {}",
        ring.len(),
        signer,
        m,
        b
    );

    if ring.is_empty() {
        error!("リングが空です。署名を生成できません。");
        return Err(RingError::EmptyRing.into());
    }
    if signer >= ring.len() {
        error!(
            "署名者のインデックス {} がリングサイズ {} を超えています。",
            signer,
            ring.len()
        );
        return Err(RingError::InvalidSignerIndex.into());
    }

    let mut rng = thread_rng();
    let hash = Sha3_256::digest(m);
    debug!("ring_sign: hash = {:?}", hash);
    let k = BigUint::from_bytes_be(&hash);
    debug!("ring_sign: k = {}", k);

    let r = ring.len();
    let mut xs: Vec<BigUint> = vec![BigUint::zero(); r];
    let mut ys: Vec<BigUint> = vec![BigUint::zero(); r];
    debug!("ring_sign: xs = {:?}, ys = {:?}", xs, ys);

    let v = rng.gen_biguint(b as u64);
    debug!("ring_sign: v = {}", v);

    // 署名者以外のメンバーについて、ランダムな寄与を生成
    for i in 0..r {
        if i == signer {
            continue;
        }
        xs[i] = rng.gen_biguint(b as u64);
        debug!("ring_sign: xs[{}] = {}", i, xs[i]);
        ys[i] = g(&ring[i], &xs[i], b);
        debug!("ring_sign: ys[{}] = {}", i, ys[i]);
    }

    let mut t = v.clone();
    debug!("ring_sign: initial t = {}", t);
    let mut i = (signer + 1) % r;
    while i != signer {
        let y_xor_t = ys[i].clone() ^ t.clone();
        debug!("ring_sign: y_xor_t (for i={}) = {}", i, y_xor_t);
        t = e_k(&k, &y_xor_t, b);
        debug!("ring_sign: t (for i={}) = {}", i, t);
        i = (i + 1) % r;
    }

    // 署名者に対する計算
    let d_k_v = d_k(&k, &v, b);
    debug!("ring_sign: d_k(v) = {}", d_k_v);
    let y_s = d_k_v ^ t;
    debug!("ring_sign: y_s = {}", y_s);
    ys[signer] = y_s.clone();

    // 署名者の秘密鍵を用いて xs を求める（KeyPairではなく署名者の秘密鍵を直接使用）
    xs[signer] = g_inverse(signer_secret, &y_s, b);
    debug!("ring_sign: xs[{}] = {}", signer, xs[signer]);

    let ring_signature = RingSignature { v, xs };
    info!("リング署名生成完了: ring_signature = {:?}", ring_signature);
    Ok(ring_signature)
}

/// リング署名検証
pub fn ring_verify(ring: &[PublicKey], sig: &RingSignature, m: &[u8], b: usize) -> Result<bool> {
    info!(
        "リング署名検証開始: ring_size = {}, sig = {:?}, m = {:?}, b = {}",
        ring.len(),
        sig,
        m,
        b
    );
    let hash = Sha3_256::digest(m);
    debug!("ring_verify: hash = {:?}", hash);
    let k = BigUint::from_bytes_be(&hash);
    debug!("ring_verify: k = {}", k);

    let r = ring.len();
    let mut t = sig.v.clone();
    debug!("ring_verify: initial t = {}", t);

    for i in 0..r {
        let y = g(&ring[i], &sig.xs[i], b);
        debug!("ring_verify: y[{}] = {}", i, y);
        let y_xor_t = y ^ t;
        debug!("ring_verify: y_xor_t[{}] = {}", i, y_xor_t);
        t = e_k(&k, &y_xor_t, b);
        debug!("ring_verify: t[{}] = {}", i, t);
    }

    let verification = t == sig.v;
    info!("リング署名検証結果: {}", verification);
    Ok(verification)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::COMMON_DOMAIN_BIT_LENGTH_ADDITION;
    use crate::rsa::generate_keypair;
    use crate::rsa::KeyPair;
    use crate::rsa::PublicKey;
    use num_traits::One;
    use rand::thread_rng;

    const TEST_RSA_BITS: usize = 2048; // Use 2048 bits for tests

    #[test]
    fn test_ring_sign_success() -> Result<()> {
        let mut rng = thread_rng();
        let rsa_bits = TEST_RSA_BITS; // Use constant
        let mut ring: Vec<KeyPair> = Vec::new();
        for _ in 0..3 {
            ring.push(generate_keypair(rsa_bits, &mut rng)?);
        }
        let b = ring.iter().map(|kp| kp.public.n.bits()).max().unwrap() as usize
            + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let message = b"Ring Signature Test";
        let ring_sig = ring_sign(
            &ring
                .iter()
                .map(|kp| kp.public.clone())
                .collect::<Vec<PublicKey>>()
                .as_slice(),
            0,
            &ring[0].secret,
            message,
            b,
        )?;
        let ring_pubs: Vec<PublicKey> = ring.iter().map(|kp| kp.public.clone()).collect();
        assert!(ring_verify(&ring_pubs, &ring_sig, message, b)?);
        Ok(())
    }

    #[test]
    fn test_ring_sign_fail() -> Result<()> {
        let mut rng = thread_rng();
        let rsa_bits = TEST_RSA_BITS; // Use constant
        let mut ring: Vec<KeyPair> = Vec::new();
        for _ in 0..3 {
            ring.push(generate_keypair(rsa_bits, &mut rng)?);
        }
        let b = ring.iter().map(|kp| kp.public.n.bits()).max().unwrap() as usize
            + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let message = b"Ring Signature Test";
        let ring_sig = ring_sign(
            &ring
                .iter()
                .map(|kp| kp.public.clone())
                .collect::<Vec<PublicKey>>()
                .as_slice(),
            0,
            &ring[0].secret,
            message,
            b,
        )?;
        let ring_pubs: Vec<PublicKey> = ring.iter().map(|kp| kp.public.clone()).collect();
        let wrong_message = b"Wrong Ring Signature Test";
        let wrong_hash = Sha3_256::digest(wrong_message);
        let _wrong_m = BigUint::from_bytes_be(&wrong_hash) % (BigUint::one() << b);
        assert!(!ring_verify(&ring_pubs, &ring_sig, wrong_message, b)?);
        Ok(())
    }
    // エラーハンドリングのテスト (空のリング)
    #[test]
    fn test_ring_sign_empty_ring() {
        let rsa_bits = TEST_RSA_BITS; // Use constant
        let ring: Vec<KeyPair> = Vec::new(); // 空のリング
        let b = rsa_bits + COMMON_DOMAIN_BIT_LENGTH_ADDITION; // 仮の b
        let message = b"Empty Ring Test";
        let result = ring_sign(
            &ring
                .iter()
                .map(|kp| kp.public.clone())
                .collect::<Vec<PublicKey>>()
                .as_slice(),
            0,
            &SecretKey {
                d: BigUint::one(),
                n: BigUint::one(),
            }, // ダミー
            message,
            b,
        );
        assert!(result.is_err(), "空のリングではErrを返すべき");
    }

    #[test]
    fn test_ring_sign_invalid_signer_index() {
        let mut rng = thread_rng();
        let rsa_bits = TEST_RSA_BITS; // Use constant
        let mut ring: Vec<KeyPair> = Vec::new();
        for _ in 0..3 {
            ring.push(generate_keypair(rsa_bits, &mut rng).unwrap());
        }
        let b = ring.iter().map(|kp| kp.public.n.bits()).max().unwrap() as usize
            + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let message = b"Ring Signature Test";
        let result = ring_sign(
            &ring
                .iter()
                .map(|kp| kp.public.clone())
                .collect::<Vec<PublicKey>>()
                .as_slice(),
            ring.len(), // 無効なインデックス
            &ring[0].secret,
            message,
            b,
        );
        assert!(result.is_err(), "不正なインデックスではErrを返すべき");
    }

    #[test]
    fn test_ring_sign_various_signers() -> Result<()> {
        let mut rng = thread_rng();
        let rsa_bits = TEST_RSA_BITS; // Use constant
        let ring_size = 5; // リングサイズを固定
        let mut ring: Vec<KeyPair> = Vec::new();
        for _ in 0..ring_size {
            ring.push(generate_keypair(rsa_bits, &mut rng)?);
        }
        let b = ring.iter().map(|kp| kp.public.n.bits()).max().unwrap() as usize
            + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let message = b"Ring Signature Test";
        let ring_pubs: Vec<PublicKey> = ring.iter().map(|kp| kp.public.clone()).collect();

        // 各署名者インデックスで署名を生成し、検証
        for signer_index in 0..ring_size {
            let ring_sig = ring_sign(
                &ring_pubs,
                signer_index,
                &ring[signer_index].secret, // 正しい秘密鍵を使用
                message,
                b,
            )?;
            assert!(
                ring_verify(&ring_pubs, &ring_sig, message, b)?,
                "Verification failed for signer {}",
                signer_index
            );
        }
        Ok(())
    }
}
