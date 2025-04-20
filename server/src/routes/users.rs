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

pub fn router() -> Router {
    Router::new().route("/keys", axum::routing::get(get_public_keys))
}

async fn get_public_keys(
    Query(query): Query<PublicKeysQuery>,
) -> Result<Json<Vec<PublicKeyDto>>, (StatusCode, String)> {
    let mut result = Vec::with_capacity(query.names.len());
    for name in &query.names {
        // Check cache: Some(Some) -> push; Some(None) -> error
        let cached_opt = {
            let cache = KEY_CACHE.read().await;
            cache.get(name).cloned()
        };
        if let Some(opt_dto) = cached_opt {
            match opt_dto {
                Some(dto) => {
                    result.push(dto);
                    continue;
                }
                None => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("No valid signing key for {}", name),
                    ))
                }
            }
        }
        // Fetch from Keybase
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
        // Parse PGP armored, cache and error on no valid signing key
        match load_public_key_from_pgp_str(&text) {
            Ok(key) => {
                let dto = PublicKeyDto {
                    n: key.n.to_string(),
                    e: key.e.to_string(),
                };
                let mut cache = KEY_CACHE.write().await;
                cache.insert(name.clone(), Some(dto.clone()));
                result.push(dto);
            }
            Err(e) if e.to_string().contains("No valid signing key") => {
                let mut cache = KEY_CACHE.write().await;
                cache.insert(name.clone(), None);
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("No valid signing key for {}", name),
                ));
            }
            Err(e) => return Err((StatusCode::BAD_REQUEST, e.to_string())),
        }
    }
    Ok(Json(result))
}
