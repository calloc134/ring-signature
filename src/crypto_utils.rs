use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use log::{debug, trace};
use num_bigint::BigUint;
use num_traits::One;
use sha3::{Digest, Sha3_256};

pub const FIXED_NONCE: [u8; 12] = [0x24u8; 12]; // 固定nonceを定数化

/// 対称鍵暗号関数 e_k (暗号化)
pub fn e_k(k: &BigUint, x: &BigUint, b: usize) -> BigUint {
    trace!("e_k: k = {}, x = {}, b = {}", k, x, b);
    let num_bytes = (b + 7) / 8;
    debug!("e_k: num_bytes = {}", num_bytes);

    let modulus = BigUint::one() << b;
    let x_mod = x % &modulus;
    debug!("e_k: x_mod = {}", x_mod);

    let mut plaintext = x_mod.to_bytes_be();
    debug!("e_k: plaintext (before padding) = {:?}", plaintext);

    if plaintext.len() < num_bytes {
        let mut padded = vec![0u8; num_bytes - plaintext.len()];
        padded.extend_from_slice(&plaintext);
        plaintext = padded;
    } else if plaintext.len() > num_bytes {
        plaintext = plaintext[plaintext.len() - num_bytes..].to_vec();
    }
    debug!("e_k: plaintext (after padding) = {:?}", plaintext);

    let k_bytes = k.to_bytes_be();
    let derived_key = Sha3_256::digest(&k_bytes);
    debug!("e_k: derived_key = {:?}", derived_key);

    let nonce = FIXED_NONCE;
    debug!("e_k: nonce = {:?}", nonce);

    let mut cipher = ChaCha20::new(derived_key.as_slice().into(), &nonce.into());
    let mut buffer = plaintext.clone();

    cipher.apply_keystream(&mut buffer);
    debug!("e_k: encrypted buffer = {:?}", buffer);

    let result = BigUint::from_bytes_be(&buffer);
    trace!("e_k: result = {}", result);
    result
}

/// 対称鍵暗号関数 d_k (復号)
#[inline]
pub fn d_k(k: &BigUint, x: &BigUint, b: usize) -> BigUint {
    trace!("d_k: k = {}, x = {}, b = {}", k, x, b);
    let result = e_k(k, x, b);
    trace!("d_k: result = {}", result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::RandBigInt;
    use rand::thread_rng;

    #[test]
    fn test_symmetric_encryption() {
        let mut rng = thread_rng();
        let b = 256;
        for _ in 0..10 {
            let k = rng.gen_biguint(b as u64);
            let x = rng.gen_biguint(b as u64);
            let encrypted = e_k(&k, &x, b);
            let decrypted = d_k(&k, &encrypted, b);
            assert_eq!(decrypted, x % (BigUint::one() << b));
        }
    }
    // e_k 関数のテスト（bの値を変える）
    #[test]
    fn test_e_k_different_b() {
        let mut rng = thread_rng();
        let k = rng.gen_biguint(256); //256ビットキー
        let x = rng.gen_biguint(256);

        let b1 = 128;
        let encrypted1 = e_k(&k, &x, b1);
        let decrypted1 = d_k(&k, &encrypted1, b1);
        assert_eq!(
            x.clone() & ((BigUint::one() << b1) - BigUint::one()),
            decrypted1,
            "b=128で失敗"
        );

        let b2 = 64;
        let encrypted2 = e_k(&k, &x, b2);
        let decrypted2 = d_k(&k, &encrypted2, b2);
        assert_eq!(
            x.clone() & ((BigUint::one() << b2) - BigUint::one()),
            decrypted2,
            "b=64で失敗"
        );
    }

    // d_k関数のテスト (bの値を変える)
    #[test]
    fn test_d_k_different_b() {
        let mut rng = thread_rng();
        let k = rng.gen_biguint(256);
        let x = rng.gen_biguint(256);

        let b1 = 128;
        let encrypted1 = e_k(&k, &x, b1); //先にe_kで暗号化
        let decrypted1 = d_k(&k, &encrypted1, b1);
        assert_eq!(
            x.clone() & ((BigUint::one() << b1) - BigUint::one()),
            decrypted1,
            "b=128で失敗"
        );

        let b2 = 64;
        let encrypted2 = e_k(&k, &x, b2); //先にe_kで暗号化
        let decrypted2 = d_k(&k, &encrypted2, b2);
        assert_eq!(
            x.clone() & ((BigUint::one() << b2) - BigUint::one()),
            decrypted2,
            "b=64で失敗"
        );
    }
    #[test]
    fn test_encryption_decryption() {
        let mut rng = thread_rng();
        let b = 256; //  ビット長
        for _ in 0..10 {
            let k = rng.gen_biguint(b as u64); //ランダムキー
            let x = rng.gen_biguint(b as u64); //ランダム平文

            let masked_x = e_k(&k, &x, b); //暗号化
            let unmasked_x = d_k(&k, &masked_x, b); // 復号

            assert_eq!(x, unmasked_x); // 元の値と一致することを確認
        }
    }
}
