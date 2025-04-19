use common::constants::COMMON_DOMAIN_BIT_LENGTH_ADDITION;
use common::ring::{ring_sign, ring_verify};
use common::rsa::{load_keypair_from_pgp_str, PublicKey, SecretKey};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize)]
struct PublicKeyDto {
    n: String,
    e: String,
}

#[derive(Serialize, Deserialize)]
struct KeyPairDto {
    public: PublicKeyDto,
    secret: SecretKeyDto,
}

#[derive(Serialize, Deserialize)]
struct SecretKeyDto {
    n: String,
    d: String,
}

#[derive(Serialize, Deserialize)]
struct RingSignatureDto {
    v: String,
    xs: Vec<String>,
}

#[wasm_bindgen]
pub fn parse_keypair(armored: &str, password: Option<String>) -> Result<JsValue, JsValue> {
    let kp = load_keypair_from_pgp_str(armored, password.as_deref())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let dto = KeyPairDto {
        public: PublicKeyDto {
            n: kp.public.n.to_string(),
            e: kp.public.e.to_string(),
        },
        secret: SecretKeyDto {
            n: kp.secret.n.to_string(),
            d: kp.secret.d.to_string(),
        },
    };
    to_value(&dto).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn generate_ring_signature(
    pubkeys_js: &JsValue,
    keypair_js: &JsValue,
    message: &[u8],
) -> Result<JsValue, JsValue> {
    // Deserialize inputs
    let pub_dtos: Vec<PublicKeyDto> =
        from_value(pubkeys_js.clone()).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let kp_dto: KeyPairDto =
        from_value(keypair_js.clone()).map_err(|e| JsValue::from_str(&e.to_string()))?;
    // Convert DTOs to internal types
    let pubkeys: Vec<PublicKey> = pub_dtos
        .into_iter()
        .map(|d| PublicKey {
            n: BigUint::parse_bytes(d.n.as_bytes(), 10).unwrap(),
            e: BigUint::parse_bytes(d.e.as_bytes(), 10).unwrap(),
        })
        .collect();
    let secret = SecretKey {
        n: BigUint::parse_bytes(kp_dto.secret.n.as_bytes(), 10).unwrap(),
        d: BigUint::parse_bytes(kp_dto.secret.d.as_bytes(), 10).unwrap(),
    };
    // Determine domain bit length b
    let max_bits = pubkeys.iter().map(|p| p.n.bits()).max().unwrap_or(0) as usize;
    let b = max_bits + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
    // Use index 0 as signer
    let sig = ring_sign(&pubkeys, 0, &secret, message, b)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    // Build DTO
    let dto = RingSignatureDto {
        v: sig.v.to_string(),
        xs: sig.xs.into_iter().map(|x| x.to_string()).collect(),
    };
    to_value(&dto).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn verify_ring_signature(
    pubkeys_js: &JsValue,
    sig_js: &JsValue,
    message: &[u8],
) -> Result<bool, JsValue> {
    let pub_dtos: Vec<PublicKeyDto> =
        from_value(pubkeys_js.clone()).map_err(|e| JsValue::from_str(&e.to_string()))?;
    #[derive(Deserialize)]
    struct SigDto {
        v: String,
        xs: Vec<String>,
    }
    let sig_dto: SigDto =
        from_value(sig_js.clone()).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pubkeys: Vec<PublicKey> = pub_dtos
        .into_iter()
        .map(|d| PublicKey {
            n: BigUint::parse_bytes(d.n.as_bytes(), 10).unwrap(),
            e: BigUint::parse_bytes(d.e.as_bytes(), 10).unwrap(),
        })
        .collect();
    let xs: Vec<BigUint> = sig_dto
        .xs
        .into_iter()
        .map(|s| BigUint::parse_bytes(s.as_bytes(), 10).unwrap())
        .collect();
    let v = BigUint::parse_bytes(sig_dto.v.as_bytes(), 10).unwrap();
    let max_bits = pubkeys.iter().map(|p| p.n.bits()).max().unwrap_or(0) as usize;
    let b = max_bits + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
    ring_verify(&pubkeys, &common::ring::RingSignature { v, xs }, message, b)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
