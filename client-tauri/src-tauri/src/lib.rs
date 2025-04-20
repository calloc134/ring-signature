// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use common::constants::COMMON_DOMAIN_BIT_LENGTH_ADDITION;
use common::ring::RingSignature;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct SignatureDto {
    v: String,
    xs: Vec<String>,
}

#[derive(Deserialize)]
struct PublicKeyDto {
    n: String,
    e: String,
}

#[derive(Deserialize)]
struct RingSignatureInput {
    v: String,
    xs: Vec<String>,
}

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
fn ring_sign(
    pubkeys: Vec<PublicKeyDto>,
    armored_secret: String,
    password: Option<String>,
    message: String,
) -> Result<SignatureDto, String> {
    let pkeys: Vec<common::rsa::PublicKey> = pubkeys
        .into_iter()
        .map(|pk| {
            let n = BigUint::parse_bytes(pk.n.as_bytes(), 10).ok_or("Invalid n")?;
            let e = BigUint::parse_bytes(pk.e.as_bytes(), 10).ok_or("Invalid e")?;
            Ok(common::rsa::PublicKey { n, e })
        })
        .collect::<Result<_, &str>>()
        .map_err(|e| e.to_string())?;
    let kp = common::rsa::load_keypair_from_pgp_str(&armored_secret, password.as_deref())
        .map_err(|e| e.to_string())?;
    let max_bits = pkeys.iter().map(|pk| pk.n.bits()).max().unwrap_or(0) as usize
        + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
    let sig = common::ring::ring_sign(&pkeys, 0, &kp.secret, message.as_bytes(), max_bits)
        .map_err(|e| e.to_string())?;
    Ok(SignatureDto {
        v: sig.v.to_string(),
        xs: sig.xs.into_iter().map(|x| x.to_string()).collect(),
    })
}

#[tauri::command]
fn ring_verify(
    pubkeys: Vec<PublicKeyDto>,
    signature: RingSignatureInput,
    message: String,
) -> Result<bool, String> {
    let pkeys: Vec<common::rsa::PublicKey> = pubkeys
        .into_iter()
        .map(|pk| {
            let n = BigUint::parse_bytes(pk.n.as_bytes(), 10).ok_or("Invalid n")?;
            let e = BigUint::parse_bytes(pk.e.as_bytes(), 10).ok_or("Invalid e")?;
            Ok(common::rsa::PublicKey { n, e })
        })
        .collect::<Result<_, &str>>()
        .map_err(|e| e.to_string())?;
    let sig = RingSignature {
        v: BigUint::parse_bytes(signature.v.as_bytes(), 10).ok_or("Invalid v")?,
        xs: signature
            .xs
            .iter()
            .map(|x| BigUint::parse_bytes(x.as_bytes(), 10).ok_or("Invalid xs"))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "Invalid xs")?,
    };
    let max_bits = pkeys.iter().map(|pk| pk.n.bits()).max().unwrap_or(0) as usize
        + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
    let ok = common::ring::ring_verify(&pkeys, &sig, message.as_bytes(), max_bits)
        .map_err(|e| e.to_string())?;
    Ok(ok)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![greet, ring_sign, ring_verify])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
