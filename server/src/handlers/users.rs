use axum::{
    extract::Query,
    http::StatusCode,
    routing::get,
    Json, Router,
};
use crate::models::{PublicKeyDto, PublicKeysQuery};
use crate::utils::{get_public_keys_for_users, pad_hex};

pub fn router() -> Router {
    Router::new().route("/users", get(get_public_keys))
}

async fn get_public_keys(
    Query(params): Query<PublicKeysQuery>,
) -> Result<Json<Vec<PublicKeyDto>>, (StatusCode, String)> {
    let keys = get_public_keys_for_users(&params.names).await?;
    let dtos = keys
        .into_iter()
        .map(|pk| PublicKeyDto {
            n: pad_hex(&pk.n.to_str_radix(16)),
            e: pad_hex(&pk.e.to_str_radix(16)),
        })
        .collect();
    Ok(Json(dtos))
}
