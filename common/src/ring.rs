use crate::crypto_utils::{d_k, e_k};
use crate::error::RingError;
use crate::rsa::{g, g_inverse, PublicKey, SecretKey};
use anyhow::Result;
use log::{debug, error, info};
use num_bigint::{BigUint, RandBigInt};
use num_traits::Zero;
use rand::thread_rng;
// ハッシュ関数 (SHA3-256)
use sha3::{Digest, Sha3_256};
use std::vec::Vec;

// リング署名を表す構造体
#[derive(Debug)]
pub struct RingSignature {
    // グルー値 (検証の起点となる値)
    pub v: BigUint,
    // 各リングメンバーの寄与値 (x_i)
    pub xs: Vec<BigUint>,
}

/// リング署名生成
/// ring: リングメンバーの公開鍵リスト
/// signer: 署名者のインデックス
/// signer_secret: 署名者の秘密鍵
/// m: 署名対象のメッセージ
/// b: 共通ドメインのビット長
pub fn ring_sign(
    ring: &[PublicKey],
    signer: usize,
    signer_secret: &SecretKey,
    m: &[u8],
    b: usize,
) -> Result<RingSignature> {
    // infoには主要パラメータのみ、詳細はdebugで出力
    info!(
        "リング署名生成開始: ring_size = {}, signer = {}, m_len = {}, b = {}",
        ring.len(),
        signer,
        m.len(),
        b
    );
    debug!("リング署名生成開始: m = {:?}", m);

    // リングが空の場合エラー
    if ring.is_empty() {
        error!("リングが空です。署名を生成できません。");
        return Err(RingError::EmptyRing.into());
    }
    // 署名者インデックスが無効な場合エラー
    if signer >= ring.len() {
        error!(
            "署名者のインデックス {} がリングサイズ {} を超えています。",
            signer,
            ring.len()
        );
        return Err(RingError::InvalidSignerIndex.into());
    }

    let mut rng = thread_rng();
    // メッセージのハッシュ値を計算 (対称鍵暗号の鍵 k として使用)
    let hash = Sha3_256::digest(m);
    debug!("ring_sign: hash = {:?}", hash);
    let k = BigUint::from_bytes_be(&hash);
    debug!("ring_sign: k = {}", k);

    // リングのメンバー数
    let r = ring.len();
    // 各メンバーの寄与 x_i を格納するベクトル (初期値 0)
    let mut xs: Vec<BigUint> = vec![BigUint::zero(); r];
    // 各メンバーの中間値 y_i = g(x_i) を格納するベクトル (初期値 0)
    let mut ys: Vec<BigUint> = vec![BigUint::zero(); r];
    debug!("ring_sign: xs = {:?}, ys = {:?}", xs, ys);

    // グルー値 v をランダムに生成 (b ビット)
    let v = rng.gen_biguint(b as u64);
    debug!("ring_sign: v = {}", v);

    // 署名者以外のメンバーについて処理
    for i in 0..r {
        if i == signer {
            continue; // 署名者は後で処理
        }
        // ランダムな寄与 x_i を生成 (b ビット)
        xs[i] = rng.gen_biguint(b as u64);
        debug!("ring_sign: xs[{}] = {}", i, xs[i]);
        // 中間値 y_i = g(x_i) を計算
        ys[i] = g(&ring[i], &xs[i]);
        debug!("ring_sign: ys[{}] = {}", i, ys[i]);
    }

    // リング方程式 C_{k,v}(x_0, ..., x_{r-1}) = v を満たすように計算
    // t は計算途中の値 (初期値は v)
    let mut t = v.clone();
    debug!("ring_sign: initial t = {}", t);
    // 署名者の次のメンバーから順に計算
    let mut i = (signer + 1) % r;
    while i != signer {
        // y_i と t の XOR を計算
        let y_xor_t = ys[i].clone() ^ t.clone();
        debug!("ring_sign: y_xor_t (for i={}) = {}", i, y_xor_t);
        // 対称鍵暗号 e_k を適用して次の t を計算
        t = e_k(&k, &y_xor_t, b);
        debug!("ring_sign: t (for i={}) = {}", i, t);
        // 次のメンバーへ
        i = (i + 1) % r;
    }

    // 署名者に対する計算
    // 対称鍵暗号の復号 d_k(v) を計算
    let d_k_v = d_k(&k, &v, b);
    debug!("ring_sign: d_k(v) = {}", d_k_v);
    // 署名者の中間値 y_s を計算 (y_s = d_k(v) XOR t)
    let y_s = d_k_v ^ t;
    debug!("ring_sign: y_s = {}", y_s);
    ys[signer] = y_s.clone();

    // 署名者の秘密鍵を用いて寄与 x_s を計算 (x_s = g⁻¹(y_s))
    xs[signer] = g_inverse(signer_secret, &y_s);
    debug!("ring_sign: xs[{}] = {}", signer, xs[signer]);

    // リング署名オブジェクトを作成
    let ring_signature = RingSignature { v, xs };
    // infoには主要パラメータのみ、詳細はdebugで出力
    info!(
        "リング署名生成完了: v bits = {}, xs_len = {}",
        ring_signature.v.bits(),
        ring_signature.xs.len()
    );
    debug!("リング署名生成完了: ring_signature = {:?}", ring_signature);
    Ok(ring_signature)
}

/// リング署名検証
/// ring: リングメンバーの公開鍵リスト
/// sig: 検証対象のリング署名
/// m: 検証対象のメッセージ
/// b: 共通ドメインのビット長
pub fn ring_verify(ring: &[PublicKey], sig: &RingSignature, m: &[u8], b: usize) -> Result<bool> {
    // infoには主要パラメータのみ、詳細はdebugで出力
    info!(
        "リング署名検証開始: ring_size = {}, sig.v bits = {}, sig.xs_len = {}, m_len = {}, b = {}",
        ring.len(),
        sig.v.bits(),
        sig.xs.len(),
        m.len(),
        b
    );
    debug!("リング署名検証開始: sig = {:?}, m = {:?}", sig, m);
    // メッセージのハッシュ値を計算 (対称鍵暗号の鍵 k として使用)
    let hash = Sha3_256::digest(m);
    debug!("ring_verify: hash = {:?}", hash);
    let k = BigUint::from_bytes_be(&hash);
    debug!("ring_verify: k = {}", k);

    // リングのメンバー数
    let r = ring.len();
    // 検証計算のための中間変数 t (初期値は署名のグルー値 v)
    let mut t = sig.v.clone();
    debug!("ring_verify: initial t = {}", t);

    // 各リングメンバーについて検証計算を実行
    for i in 0..r {
        // メンバー i の公開鍵と寄与 x_i から中間値 y_i = g(x_i) を計算
        let y = g(&ring[i], &sig.xs[i]);
        debug!("ring_verify: y[{}] = {}", i, y);
        // y_i と t の XOR を計算
        let y_xor_t = y ^ t;
        debug!("ring_verify: y_xor_t[{}] = {}", i, y_xor_t);
        // 対称鍵暗号 e_k を適用して次の t を計算
        t = e_k(&k, &y_xor_t, b);
        debug!("ring_verify: t[{}] = {}", i, t);
    }

    // 最終的な計算結果 t が元のグルー値 v と一致するかどうかで検証
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

    // テストで使用するRSA鍵のビット長
    const TEST_RSA_BITS: usize = 2048;

    // リング署名の生成と検証が成功するかのテスト
    #[test]
    fn test_ring_sign_success() -> Result<()> {
        let mut rng = thread_rng();
        let rsa_bits = TEST_RSA_BITS;
        let mut ring: Vec<KeyPair> = Vec::new();
        // 3人のメンバーでリングを構成
        for _ in 0..3 {
            ring.push(generate_keypair(rsa_bits, &mut rng)?);
        }
        // リング内の最大鍵長から共通ドメインのビット長 b を計算
        let b = ring.iter().map(|kp| kp.public.n.bits()).max().unwrap() as usize
            + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let message = b"Ring Signature Test";
        // メンバー 0 が署名者として署名生成
        let ring_sig = ring_sign(
            &ring
                .iter()
                .map(|kp| kp.public.clone())
                .collect::<Vec<PublicKey>>()
                .as_slice(),
            0,               // 署名者のインデックス
            &ring[0].secret, // 署名者の秘密鍵
            message,
            b,
        )?;
        // 検証用の公開鍵リスト
        let ring_pubs: Vec<PublicKey> = ring.iter().map(|kp| kp.public.clone()).collect();
        // 署名検証
        assert!(ring_verify(&ring_pubs, &ring_sig, message, b)?);
        Ok(())
    }

    // リング署名検証が異なるメッセージで失敗するかのテスト
    #[test]
    fn test_ring_sign_fail() -> Result<()> {
        let mut rng = thread_rng();
        let rsa_bits = TEST_RSA_BITS;
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
        // 異なるメッセージで検証
        let wrong_message = b"Wrong Ring Signature Test";
        // 検証が失敗することを確認
        assert!(!ring_verify(&ring_pubs, &ring_sig, wrong_message, b)?);
        Ok(())
    }

    // リング署名生成時にリングが空の場合のエラーハンドリングテスト
    #[test]
    fn test_ring_sign_empty_ring() {
        let rsa_bits = TEST_RSA_BITS;
        let ring: Vec<KeyPair> = Vec::new(); // 空のリング
        let b = rsa_bits + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let message = b"Empty Ring Test";
        // ダミーの秘密鍵
        let dummy_secret = SecretKey {
            d: BigUint::one(),
            n: BigUint::one(),
        };
        // 署名生成を試みる
        let result = ring_sign(
            &ring
                .iter()
                .map(|kp| kp.public.clone())
                .collect::<Vec<PublicKey>>()
                .as_slice(),
            0,
            &dummy_secret,
            message,
            b,
        );
        // エラーが発生することを確認
        assert!(result.is_err(), "空のリングではErrを返すべき");
    }

    // リング署名生成時に署名者インデックスが無効な場合のエラーハンドリングテスト
    #[test]
    fn test_ring_sign_invalid_signer_index() {
        let mut rng = thread_rng();
        let rsa_bits = TEST_RSA_BITS;
        let mut ring: Vec<KeyPair> = Vec::new();
        for _ in 0..3 {
            ring.push(generate_keypair(rsa_bits, &mut rng).unwrap());
        }
        let b = ring.iter().map(|kp| kp.public.n.bits()).max().unwrap() as usize
            + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let message = b"Ring Signature Test";
        // 署名生成を試みる (無効なインデックスを使用)
        let result = ring_sign(
            &ring
                .iter()
                .map(|kp| kp.public.clone())
                .collect::<Vec<PublicKey>>()
                .as_slice(),
            ring.len(), // 無効なインデックス (ring.len() は 0 から始まるインデックスの範囲外)
            &ring[0].secret, // 秘密鍵は任意
            message,
            b,
        );
        // エラーが発生することを確認
        assert!(result.is_err(), "不正なインデックスではErrを返すべき");
    }

    // リング内の異なるメンバーが署名者となった場合にそれぞれ検証が成功するかのテスト
    #[test]
    fn test_ring_sign_various_signers() -> Result<()> {
        let mut rng = thread_rng();
        let rsa_bits = TEST_RSA_BITS;
        let ring_size = 5;
        let mut ring: Vec<KeyPair> = Vec::new();
        for _ in 0..ring_size {
            ring.push(generate_keypair(rsa_bits, &mut rng)?);
        }
        let b = ring.iter().map(|kp| kp.public.n.bits()).max().unwrap() as usize
            + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
        let message = b"Ring Signature Test";
        let ring_pubs: Vec<PublicKey> = ring.iter().map(|kp| kp.public.clone()).collect();

        // 各メンバーを署名者としてテスト
        for signer_index in 0..ring_size {
            // 署名生成
            let ring_sig = ring_sign(
                &ring_pubs,
                signer_index,
                &ring[signer_index].secret, // 対応する秘密鍵を使用
                message,
                b,
            )?;
            // 署名検証
            assert!(
                ring_verify(&ring_pubs, &ring_sig, message, b)?,
                "Verification failed for signer {}",
                signer_index
            );
        }
        Ok(())
    }
}
