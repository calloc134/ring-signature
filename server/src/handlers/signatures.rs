use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use crate::models::{CreateSignatureDto, CreateSignatureResponse, SignatureRecordDto};
use crate::usecases::signature_usecase::{create_signature as uc_create, fetch_signatures as uc_fetch};
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
    uc_create(&pool, payload).await.map(Json)
}

async fn fetch_signatures(
    Extension(pool): Extension<PgPool>,
    Path(username): Path<String>,
) -> Result<Json<Vec<SignatureRecordDto>>, (StatusCode, String)> {
    uc_fetch(&pool, username).await.map(Json)
}