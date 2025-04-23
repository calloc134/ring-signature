use crate::models::{PublicKeyDto, PublicKeysQuery};
use crate::utils::get_key; // Import get_key from utils
use axum::{extract::Query, http::StatusCode, Json, Router};

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
