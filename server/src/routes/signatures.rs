use crate::db::{get_signatures_for_user, insert_signature, CreateSignatureRequest};
use crate::models::{CreateSignatureDto, CreateSignatureResponse, SignatureRecordDto};
use crate::utils::get_public_keys_for_users; // Import from utils
use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
// Common crate imports for verification
use common::{
    constants::COMMON_DOMAIN_BIT_LENGTH_ADDITION,
    ring::{ring_verify, RingSignature},
    rsa::PublicKey, // Assuming PublicKey is accessible
    serialization::hex_to_biguint,
};
use num_bigint::BigUint;
use sqlx::PgPool;

pub fn router() -> Router {
    Router::new()
        .route("/signatures", post(create_signature))
        .route("/signatures/{username}", get(fetch_signatures))
}

async fn create_signature(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateSignatureDto>,
) -> Result<Json<CreateSignatureResponse>, (StatusCode, String)> {
    // --- Input Parsing and Basic Validation ---
    let v_biguint = hex_to_biguint(&payload.v)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid v format: {}", e)))?;
    let xs_biguint: Vec<BigUint> = payload
        .xs
        .iter()
        .map(|x| {
            hex_to_biguint(x).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid x format '{}': {}", x, e),
                )
            })
        })
        .collect::<Result<_, _>>()?;

    if payload.members.len() != xs_biguint.len() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Number of members does not match number of signature parts (xs)".to_string(),
        ));
    }
    if payload.members.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Member list cannot be empty".to_string(),
        ));
    }

    // --- Fetch Public Keys for Verification ---
    // NOTE: Assumes get_public_keys_for_users returns keys in the same order as payload.members
    let ring_pubs: Vec<PublicKey> = get_public_keys_for_users(&payload.members) // Call the imported function
        .await
        .map_err(|e| {
            // Propagate the status code and message from get_public_keys_for_users
            e
        })?;

    // --- Calculate Common Domain Bit Length 'b' ---
    let b = ring_pubs.iter().map(|pk| pk.n.bits()).max().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to calculate common domain bit length 'b' from fetched keys.".to_string(),
    ))? as usize
        + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

    // --- Reconstruct Ring Signature ---
    let ring_sig = RingSignature {
        v: v_biguint,
        xs: xs_biguint,
    };

    // --- Verify Signature ---
    let message_bytes = payload.message.as_bytes();
    match ring_verify(&ring_pubs, &ring_sig, message_bytes, b) {
        Ok(true) => {
            // Verification successful, proceed to save
            // Re-serialize v and xs to hex for storage consistency
            let v_hex = ring_sig.v.to_str_radix(16);
            let xs_hex: Vec<String> = ring_sig.xs.iter().map(|x| x.to_str_radix(16)).collect();

            let req = CreateSignatureRequest {
                v: v_hex,
                xs: xs_hex,
                members: payload.members, // Store original member list
                message: payload.message,
            };
            match insert_signature(&pool, req).await {
                Ok(id) => Ok(Json(CreateSignatureResponse { id })),
                Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
            }
        }
        Ok(false) => {
            // Verification failed
            Err((
                StatusCode::BAD_REQUEST,
                "Signature verification failed".to_string(),
            ))
        }
        Err(e) => {
            // Error during verification process
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error during signature verification: {}", e),
            ))
        }
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
