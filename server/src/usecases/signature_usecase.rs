use crate::domain::signature::{ring_verify, DomainRingSignature};
use crate::models::{CreateSignatureDto, CreateSignatureResponse, SignatureRecordDto};
use crate::repositories::signature_repository::{get_signatures_for_user, insert_signature};
use crate::utils::{get_public_keys_for_users, pad_hex};
use axum::http::StatusCode;
use common::{
    constants::COMMON_DOMAIN_BIT_LENGTH_ADDITION, rsa::PublicKey, serialization::hex_to_biguint,
};
use num_bigint::BigUint;
use sqlx::PgPool;

/// Business logic for creating a ring signature and storing it
pub async fn create_signature(
    pool: &PgPool,
    payload: CreateSignatureDto,
) -> Result<CreateSignatureResponse, (StatusCode, String)> {
    // parse v
    let v_hex = pad_hex(&payload.v);
    let v_biguint = hex_to_biguint(&v_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid v format: {}", e)))?;

    // parse xs
    let xs_biguint: Vec<BigUint> = payload
        .xs
        .iter()
        .map(|x| {
            let x_hex = pad_hex(x);
            hex_to_biguint(&x_hex).map_err(|e| {
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

    // fetch keys
    let ring_pubs: Vec<PublicKey> = get_public_keys_for_users(&payload.members).await?;

    // common domain bit length
    let b = ring_pubs.iter().map(|pk| pk.n.bits()).max().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to calculate common domain bit length 'b' from fetched keys.".to_string(),
    ))? as usize
        + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

    // --- Reconstruct and verify
    let ring_sig = DomainRingSignature {
        v: v_biguint,
        xs: xs_biguint,
    };
    match ring_verify(&ring_pubs, &ring_sig, payload.message.as_bytes(), b) {
        Ok(true) => {
            // serialize and store
            let v_hex = ring_sig.v.to_str_radix(16);
            let xs_hex: Vec<String> = ring_sig.xs.iter().map(|x| x.to_str_radix(16)).collect();
            let req = CreateSignatureDto {
                v: v_hex,
                xs: xs_hex,
                members: payload.members,
                message: payload.message,
            };
            let id = insert_signature(pool, req)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            Ok(CreateSignatureResponse { id })
        }
        Ok(false) => Err((
            StatusCode::BAD_REQUEST,
            "Signature verification failed".to_string(),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error during signature verification: {}", e),
        )),
    }
}

/// Business logic for fetching stored signatures for a user
pub async fn fetch_signatures(
    pool: &PgPool,
    username: String,
) -> Result<Vec<SignatureRecordDto>, (StatusCode, String)> {
    let records = get_signatures_for_user(pool, &username)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(records)
}
