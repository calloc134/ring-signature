use crate::db::{get_signatures_for_user, insert_signature, CreateSignatureRequest};
use crate::models::{CreateSignatureDto, CreateSignatureResponse, SignatureRecordDto};
use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
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
    let req = CreateSignatureRequest {
        v: payload.v,
        xs: payload.xs,
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
