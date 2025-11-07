// common/tests/adversarial_keys_intersection.rs
use common::{
    constants::COMMON_DOMAIN_BIT_LENGTH_ADDITION,
    generate_keypair,
    ring::{ring_sign, ring_verify},
    rsa::{g, KeyPair, PublicKey},
};
use hex;
use num_bigint::BigUint;
use num_integer::Integer;
use num_prime::RandPrime;
use num_traits::One;
use rand::{seq::SliceRandom, thread_rng};
use std::collections::HashSet; // Cargo.toml に既存依存あり

fn make_carmichael_pub(bits: usize) -> PublicKey {
    let mut rng = thread_rng();
    let p: BigUint = rng.gen_prime_exact(bits / 2, None);
    let q: BigUint = rng.gen_prime_exact(bits / 2, None);
    let n = &p * &q;
    let lambda = (&p - BigUint::one()).lcm(&(&q - BigUint::one()));
    PublicKey { n, e: lambda }
}

// PublicKey をセット要素として扱うため、識別子（n の BE 表現の hex）で集合化
fn pk_id(pk: &PublicKey) -> String {
    hex::encode(pk.n.to_bytes_be())
}

#[test]
fn deanonymize_by_intersection_with_partial_adversarial_keys() {
    let mut rng = thread_rng();
    let rsa_bits = 2048;

    // 真の署名者
    let signer: KeyPair = generate_keypair(rsa_bits, &mut rng).expect("keygen");
    let signer_pub = signer.public.clone();
    let signer_id = pk_id(&signer_pub);

    // 正直鍵プール（十分大きく）
    let honest_pool: Vec<KeyPair> = (0..200)
        .map(|_| generate_keypair(rsa_bits, &mut rng).unwrap())
        .collect();

    let n = 16usize; // リングサイズ
    let m = 8usize; // 悪意鍵本数（半分）
    let r = n - m; // 各リングで残る正直候補数
    let t = 3usize; // 署名本数（交差の回数）

    let mut intersection: Option<HashSet<String>> = None;

    for j in 0..t {
        // リング構成：index 0 が真の署名者、r-1 の正直デコイ＋m の悪意鍵
        let mut ring_pubs: Vec<PublicKey> = Vec::with_capacity(n);
        ring_pubs.push(signer_pub.clone());

        // ランダムに r-1 本の正直デコイを抽出（署名間で独立に入れ替わる想定）
        let mut decoys: Vec<PublicKey> = honest_pool
            .choose_multiple(&mut rng, r - 1)
            .map(|kp| kp.public.clone())
            .collect();
        ring_pubs.append(&mut decoys);

        for _ in 0..m {
            ring_pubs.push(make_carmichael_pub(rsa_bits));
        }

        let b = ring_pubs.iter().map(|pk| pk.n.bits()).max().unwrap() as usize
            + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

        let msg = format!("intersection test run {}", j);
        let sig = ring_sign(&ring_pubs, 0, &signer.secret, msg.as_bytes(), b).expect("ring_sign");
        assert!(ring_verify(&ring_pubs, &sig, msg.as_bytes(), b).unwrap());

        // 公開タグで悪意鍵位置を除外し、“正直候補”の PublicKey ID 集合を作る
        let mut survivors: HashSet<String> = HashSet::new();
        for i in 0..ring_pubs.len() {
            let y_i = g(&ring_pubs[i], &sig.xs[i]);
            let is_unit = sig.xs[i].gcd(&ring_pubs[i].n).is_one();
            let is_carm_tag = (&y_i % &ring_pubs[i].n).is_one();
            // 悪意鍵: (is_unit && is_carm_tag) → 除外
            if !(is_unit && is_carm_tag) {
                survivors.insert(pk_id(&ring_pubs[i]));
            }
        }
        // 真の署名者の公開鍵は必ず残る
        assert!(survivors.contains(&signer_id));

        // 交差
        intersection = Some(match intersection.take() {
            None => survivors,
            Some(prev) => prev.intersection(&survivors).cloned().collect(),
        });
    }

    let final_set = intersection.expect("non-empty");
    // 交差で真の署名者だけが残る（経験則として t=3 程度で収束）
    assert!(final_set.contains(&signer_id));
    assert_eq!(
        final_set.len(),
        1,
        "intersection survivors = {:?}",
        final_set
    );
}
