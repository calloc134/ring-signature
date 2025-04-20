use crate::db::{get_signatures_for_user, insert_signature, CreateSignatureRequest};
use crate::models::{CreateSignatureDto, CreateSignatureResponse, SignatureRecordDto};
use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use num_bigint::BigUint;
use sqlx::PgPool;

pub fn router() -> Router {
    Router::new()
        .route("/signatures", post(create_signature))
        .route("/signatures/:username", get(fetch_signatures))
}

async fn create_signature(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateSignatureDto>,
) -> Result<Json<CreateSignatureResponse>, (StatusCode, String)> {
    // parse provided v and xs as hex and re-serialize to ensure hex storage
    let v_hex = BigUint::parse_bytes(payload.v.as_bytes(), 16)
        .ok_or((StatusCode::BAD_REQUEST, "Invalid v".to_string()))?
        .to_str_radix(16);
    let xs_hex: Vec<String> = payload
        .xs
        .iter()
        .map(|x| {
            BigUint::parse_bytes(x.as_bytes(), 16)
                .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("Invalid x {}", x)))
                .map(|b| b.to_str_radix(16))
        })
        .collect::<Result<_, _>>()?;
    let req = CreateSignatureRequest {
        v: v_hex,
        xs: xs_hex,
        members: payload.members,
        message: payload.message,
    };
    match insert_signature(&pool, req).await {
        Ok(id) => Ok(Json(CreateSignatureResponse { id })),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

async fn fetch_signatures(
    Extension(pool): Extension<PgPool>,
    Path(username): Path<String>,
) -> Result<Json<Vec<SignatureRecordDto>>, (StatusCode, String)> {
    match get_signatures_for_user(&pool, &username).await {
        Ok(records) => {
            let dtos = records
                .into_iter()
                .map(|r| SignatureRecordDto {
                    id: r.id,
                    v: r.v,
                    message: r.message,
                    xs: r.xs,
                    members: r.members,
                    created_at: r.created_at,
                })
                .collect();
            Ok(Json(dtos))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}
