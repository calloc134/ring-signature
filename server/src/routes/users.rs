use crate::models::{PublicKeyDto, PublicKeysQuery};
use axum::{extract::Query, http::StatusCode, Json, Router};
use common::rsa::load_public_key_from_pgp_str;
use once_cell::sync::Lazy;
use reqwest::Client;
use std::collections::HashMap;
use tokio::sync::RwLock;

static KEY_CACHE: Lazy<RwLock<HashMap<String, PublicKeyDto>>> =
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
        // Check cache
        let dto_opt = {
            let cache = KEY_CACHE.read().await;
            cache.get(name).cloned()
        };
        if let Some(dto) = dto_opt {
            result.push(dto);
            continue;
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
        // Parse PGP armored
        let key = load_public_key_from_pgp_str(&text)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let dto = PublicKeyDto {
            n: key.n.to_string(),
            e: key.e.to_string(),
        };
        {
            let mut cache = KEY_CACHE.write().await;
            cache.insert(name.clone(), dto.clone());
        }
        result.push(dto);
    }
    Ok(Json(result))
}
