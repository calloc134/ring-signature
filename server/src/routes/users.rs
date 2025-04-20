use crate::models::{PublicKeyDto, PublicKeysQuery};
use axum::{extract::Query, http::StatusCode, Json, Router};
use common::rsa::load_public_key_from_pgp_str;
use once_cell::sync::Lazy;
use reqwest::Client;
use std::collections::HashMap;
use tokio::sync::RwLock;

static KEY_CACHE: Lazy<RwLock<HashMap<String, Option<PublicKeyDto>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| Client::new());

/// Fetches a public key from Keybase, returning Some(dto) or None if no valid signing key, or Err on other errors.
async fn fetch_keybase_key(name: &str) -> Result<Option<PublicKeyDto>, (StatusCode, String)> {
    let url = format!("https://keybase.io/{}/key.asc", name);
    let res = HTTP_CLIENT
        .get(&url)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    if !res.status().is_success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("Failed to fetch key for {}", name),
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
        Err(e) if e.to_string().contains("No valid signing key") => Ok(None),
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}

/// Retrieves a public key from cache or fetches and caches it. Returns Err on no valid key or other failures.
async fn get_key(name: &str) -> Result<PublicKeyDto, (StatusCode, String)> {
    // try cache read
    if let Some(opt) = { KEY_CACHE.read().await.get(name).cloned() } {
        return match opt {
            Some(dto) => Ok(dto),
            None => Err((
                StatusCode::BAD_REQUEST,
                format!("No valid signing key for {}", name),
            )),
        };
    }
    // fetch and cache
    let fetched = fetch_keybase_key(name).await?;
    KEY_CACHE
        .write()
        .await
        .insert(name.to_string(), fetched.clone());
    if let Some(dto) = fetched {
        Ok(dto)
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            format!("No valid signing key for {}", name),
        ))
    }
}

pub fn router() -> Router {
    Router::new().route("/keys", axum::routing::get(get_public_keys))
}

async fn get_public_keys(
    Query(query): Query<PublicKeysQuery>,
) -> Result<Json<Vec<PublicKeyDto>>, (StatusCode, String)> {
    let mut result = Vec::with_capacity(query.names.len());
    for name in &query.names {
        let dto = get_key(name).await?;
        result.push(dto);
    }
    Ok(Json(result))
}
