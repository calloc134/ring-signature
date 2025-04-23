use crate::models::PublicKeyDto;
use axum::http::StatusCode;
use common::rsa::{load_public_key_from_pgp_str, PublicKey}; // Added PublicKey
use common::serialization::hex_to_biguint;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::de::Deserializer;
use serde::Deserialize;
use std::collections::HashMap;
use tokio::sync::RwLock;

// --- Moved from users.rs ---
static KEY_CACHE: Lazy<RwLock<HashMap<String, Option<PublicKeyDto>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| Client::new());

/// Fetches a public key from Keybase, returning Some(dto) or None if no valid signing key, or Err on other errors.
pub async fn fetch_keybase_key(name: &str) -> Result<Option<PublicKeyDto>, (StatusCode, String)> {
    let url = format!("https://keybase.io/{}/key.asc", name);
    let res = HTTP_CLIENT
        .get(&url)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    if !res.status().is_success() {
        // Consider returning Ok(None) if 404, or specific error for other failures
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            // Treat 'not found' as 'no valid key' scenario for simplicity here
            return Ok(None);
        }
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("Failed to fetch key for {}: Status {}", name, res.status()),
        ));
    }
    let text = res
        .text()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    match load_public_key_from_pgp_str(&text) {
        Ok(key) => Ok(Some(PublicKeyDto {
            n: key.n.to_str_radix(16),
            e: key.e.to_str_radix(16),
        })),
        // Explicitly handle the "No valid signing key" case as None
        Err(e) if e.to_string().contains("No valid signing key") => Ok(None),
        // Other PGP parsing errors are treated as bad request or internal error
        Err(e) => {
            eprintln!("Error parsing PGP key for {}: {}", name, e); // Log the error server-side
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error processing key for {}: {}", name, e),
            ))
        }
    }
}

/// Retrieves a public key DTO from cache or fetches and caches it. Returns Err on no valid key or other failures.
pub async fn get_key(name: &str) -> Result<PublicKeyDto, (StatusCode, String)> {
    // try cache read
    if let Some(opt_dto) = KEY_CACHE.read().await.get(name) {
        return match opt_dto {
            Some(dto) => Ok(dto.clone()), // Clone the DTO from cache
            None => Err((
                StatusCode::NOT_FOUND, // Use NOT_FOUND when cached as explicitly having no valid key
                format!("No valid signing key found for {}", name),
            )),
        };
    }

    // Not in cache, fetch and cache
    let fetched_result = fetch_keybase_key(name).await;
    // Cache the result (Some(dto) or None) before returning
    KEY_CACHE.write().await.insert(
        name.to_string(),
        fetched_result.as_ref().ok().cloned().flatten(),
    );

    match fetched_result {
        Ok(Some(dto)) => Ok(dto),
        Ok(None) => Err((
            StatusCode::NOT_FOUND, // Use NOT_FOUND when fetched and found no valid key
            format!("No valid signing key found for {}", name),
        )),
        Err(e) => Err(e), // Propagate fetch/processing errors
    }
}
// --- End of Moved code ---

/// Fetches public keys for a list of usernames and converts them to PublicKey structs.
/// Ensures keys are returned in the same order as requested usernames.
pub async fn get_public_keys_for_users(
    usernames: &[String],
) -> Result<Vec<PublicKey>, (StatusCode, String)> {
    let mut public_keys = Vec::with_capacity(usernames.len());

    for name in usernames {
        // Use the refactored get_key function which handles caching and fetching
        let key_dto = get_key(name).await?; // Propagates errors from get_key

        // --- Add padding for odd length hex strings ---
        let n_str = if key_dto.n.len() % 2 != 0 {
            format!("0{}", key_dto.n)
        } else {
            key_dto.n.clone()
        };
        let e_str = if key_dto.e.len() % 2 != 0 {
            format!("0{}", key_dto.e)
        } else {
            key_dto.e.clone()
        };
        // --- End of padding logic ---

        // Convert hex strings (n, e) from DTO to BigUint using padded strings
        let n = hex_to_biguint(&n_str).map_err(|e| {
            // Use n_str // <--- Error likely here for 'e'
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse public key modulus 'n' for {}: {}", name, e),
            )
        })?;
        let e = hex_to_biguint(&e_str).map_err(|e| {
            // Use e_str
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Failed to parse public key exponent 'e' for {}: {}", // Error message remains the same
                    name, e
                ),
            )
        })?;

        public_keys.push(PublicKey { n, e });
    }

    // Since we iterate in order and push, the resulting Vec<PublicKey>
    // will correspond to the order of the input `usernames` slice.
    Ok(public_keys)
}

/// カンマ区切りの文字列を Vec<String> にパースします。
pub fn comma_separated<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    // まず文字列としてデシリアライズ
    let s = String::deserialize(deserializer)?;
    // カンマで分割 → トリム → 空要素を除去 → Vec<String> に変換
    Ok(s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect())
}
