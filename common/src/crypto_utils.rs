// ChaCha20 ストリーム暗号関連
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use log::{debug, trace};
use num_bigint::BigUint;
use num_traits::One;
// ハッシュ関数 (SHA3-256)
use sha3::{Digest, Sha3_256};

// ChaCha20で使用する固定ノンス (12バイト)
pub const FIXED_NONCE: [u8; 12] = [0x24u8; 12];

/// 対称鍵暗号関数 e_k (ChaCha20 を使用した暗号化)
/// k: 対称鍵 (BigUint)
/// x: 平文 (BigUint)
/// b: 共通ドメインのビット長 (出力のビット長)
pub fn e_k(k: &BigUint, x: &BigUint, b: usize) -> BigUint {
    trace!("e_k: k = {}, x = {}, b = {}", k, x, b);
    // ビット長 b から必要なバイト数を計算
    let num_bytes = (b + 7) / 8;
    debug!("e_k: num_bytes = {}", num_bytes);

    // 出力ビット長に合わせて剰余を計算
    let modulus = BigUint::one() << b;
    let x_mod = x % &modulus;
    debug!("e_k: x_mod = {}", x_mod);

    // 平文をビッグエンディアンのバイト列に変換
    let mut plaintext = x_mod.to_bytes_be();
    debug!("e_k: plaintext (before padding) = {:?}", plaintext);

    // 必要に応じてゼロパディングまたは切り捨てを行い、バイト長を num_bytes に合わせる
    if plaintext.len() < num_bytes {
        let mut padded = vec![0u8; num_bytes - plaintext.len()];
        padded.extend_from_slice(&plaintext);
        plaintext = padded;
    } else if plaintext.len() > num_bytes {
        plaintext = plaintext[plaintext.len() - num_bytes..].to_vec();
    }
    debug!("e_k: plaintext (after padding) = {:?}", plaintext);

    // 入力鍵 k から SHA3-256 を用いて ChaCha20 用の 32 バイト鍵を導出
    let k_bytes = k.to_bytes_be();
    let derived_key = Sha3_256::digest(&k_bytes);
    debug!("e_k: derived_key = {:?}", derived_key);

    // 固定ノンスを使用
    let nonce = FIXED_NONCE;
    debug!("e_k: nonce = {:?}", nonce);

    // ChaCha20 サイファーを初期化
    let mut cipher = ChaCha20::new(derived_key.as_slice().into(), &nonce.into());
    // 平文と同じサイズのバッファを用意
    let mut buffer = plaintext.clone();

    // 平文に対して ChaCha20 のキーストリームを適用 (XOR)
    cipher.apply_keystream(&mut buffer);
    debug!("e_k: encrypted buffer = {:?}", buffer);

    // 暗号化されたバイト列を BigUint に変換して返す
    let result = BigUint::from_bytes_be(&buffer);
    trace!("e_k: result = {}", result);
    result
}

/// 対称鍵暗号関数 d_k (ChaCha20 を使用した復号)
/// ChaCha20 はストリーム暗号であり、暗号化と復号の操作は同じであるため、e_k をそのまま呼び出す
#[inline]
pub fn d_k(k: &BigUint, x: &BigUint, b: usize) -> BigUint {
    trace!("d_k: k = {}, x = {}, b = {}", k, x, b);
    // e_k を呼び出して復号 (暗号化と同じ操作)
    let result = e_k(k, x, b);
    trace!("d_k: result = {}", result);
    result
}

// e_k, d_kは現状失敗しない設計なのでpanicやResult型は不要。将来失敗しうる場合はResult型に変更すること。

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::RandBigInt;
    use rand::thread_rng;

    // 対称鍵暗号化・復号の基本的なテスト
    #[test]
    fn test_symmetric_encryption() {
        let mut rng = thread_rng();
        let b = 256; // ビット長
        for _ in 0..10 {
            // ランダムな鍵と平文を生成
            let k = rng.gen_biguint(b as u64);
            let x = rng.gen_biguint(b as u64);
            // 暗号化
            let encrypted = e_k(&k, &x, b);
            // 復号
            let decrypted = d_k(&k, &encrypted, b);
            // 復号結果が元の平文 (b ビットにマスクしたもの) と一致するか確認
            assert_eq!(decrypted, x % (BigUint::one() << b));
        }
    }

    // e_k 関数が異なるビット長 b で正しく動作するかのテスト
    #[test]
    fn test_e_k_different_b() {
        let mut rng = thread_rng();
        let k = rng.gen_biguint(256); // 256ビット鍵
        let x = rng.gen_biguint(256); // 256ビット平文

        // b = 128 でテスト
        let b1 = 128;
        let encrypted1 = e_k(&k, &x, b1);
        let decrypted1 = d_k(&k, &encrypted1, b1);
        // 復号結果が元の平文を b1 ビットにマスクしたものと一致するか確認
        assert_eq!(
            x.clone() & ((BigUint::one() << b1) - BigUint::one()), // x mod 2^b1 と同等
            decrypted1,
            "b=128で失敗"
        );

        // b = 64 でテスト
        let b2 = 64;
        let encrypted2 = e_k(&k, &x, b2);
        let decrypted2 = d_k(&k, &encrypted2, b2);
        // 復号結果が元の平文を b2 ビットにマスクしたものと一致するか確認
        assert_eq!(
            x.clone() & ((BigUint::one() << b2) - BigUint::one()), // x mod 2^b2 と同等
            decrypted2,
            "b=64で失敗"
        );
    }

    // d_k 関数が異なるビット長 b で正しく動作するかのテスト (e_k のテストとほぼ同じ内容)
    #[test]
    fn test_d_k_different_b() {
        let mut rng = thread_rng();
        let k = rng.gen_biguint(256);
        let x = rng.gen_biguint(256);

        // b = 128 でテスト
        let b1 = 128;
        let encrypted1 = e_k(&k, &x, b1); // 暗号化
        let decrypted1 = d_k(&k, &encrypted1, b1); // 復号
        assert_eq!(
            x.clone() & ((BigUint::one() << b1) - BigUint::one()),
            decrypted1,
            "b=128で失敗"
        );

        // b = 64 でテスト
        let b2 = 64;
        let encrypted2 = e_k(&k, &x, b2); // 暗号化
        let decrypted2 = d_k(&k, &encrypted2, b2); // 復号
        assert_eq!(
            x.clone() & ((BigUint::one() << b2) - BigUint::one()),
            decrypted2,
            "b=64で失敗"
        );
    }
}
