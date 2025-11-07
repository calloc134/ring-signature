// common/tests/adversarial_keys_partial.rs
use common::{
    constants::COMMON_DOMAIN_BIT_LENGTH_ADDITION,
    generate_keypair,
    ring::{ring_sign, ring_verify},
    rsa::{g, KeyPair, PublicKey},
};
use num_bigint::BigUint;
use num_integer::Integer;
use num_prime::RandPrime;
use num_traits::One;
use rand::thread_rng;

// 既存と同じ悪意鍵生成：e = λ(n)
fn make_carmichael_pub(bits: usize) -> PublicKey {
    let mut rng = thread_rng();
    let p: BigUint = rng.gen_prime_exact(bits / 2, None);
    let q: BigUint = rng.gen_prime_exact(bits / 2, None);
    let n = &p * &q;
    let lambda = (&p - BigUint::one()).lcm(&(&q - BigUint::one()));
    PublicKey { n, e: lambda }
}

#[test]
fn survivors_equal_to_honest_when_partial_adversarial_single_sig() {
    let mut rng = thread_rng();
    let rsa_bits = 2048;

    // 真の署名者（正当なRSA）
    let signer: KeyPair = generate_keypair(rsa_bits, &mut rng).expect("keygen");
    let signer_pub = signer.public.clone();

    // 正直鍵プール
    let honest_pool: Vec<KeyPair> = (0..64)
        .map(|_| generate_keypair(rsa_bits, &mut rng).unwrap())
        .collect();

    let n = 16usize;
    let m = 8usize; // 半分だけ悪意鍵
    let r = n - m;

    // リングを構成：index 0 が真の署名者
    let mut ring_pubs: Vec<PublicKey> = Vec::with_capacity(n);
    ring_pubs.push(signer_pub.clone());

    // r-1 本の正直デコイをプールから選択
    for kp in honest_pool.iter().take(r - 1) {
        ring_pubs.push(kp.public.clone());
    }
    // m 本の悪意鍵を追加
    for _ in 0..m {
        ring_pubs.push(make_carmichael_pub(rsa_bits));
    }

    // ドメイン長
    let b = ring_pubs.iter().map(|pk| pk.n.bits()).max().unwrap() as usize
        + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

    let msg = b"partial adversarial - single signature";
    let sig = ring_sign(&ring_pubs, 0, &signer.secret, msg, b).expect("ring_sign");
    assert!(ring_verify(&ring_pubs, &sig, msg, b).unwrap());

    // 公開タグで悪意鍵を除外（gcd==1 を確認して安定化）
    let mut survivors = Vec::new();
    for i in 0..ring_pubs.len() {
        let y_i = g(&ring_pubs[i], &sig.xs[i]);
        let is_unit = sig.xs[i].gcd(&ring_pubs[i].n).is_one();
        let is_carm_tag = (&y_i % &ring_pubs[i].n).is_one();
        // “悪意鍵 かつ gcd==1 かつ y==1”なら非署名者として除外
        if !(is_unit && is_carm_tag) {
            survivors.push(i);
        }
    }
    // 残る候補は r 本（真の署名者＋正直デコイ）
    assert_eq!(survivors.len(), r);
    assert!(survivors.contains(&0));
}
