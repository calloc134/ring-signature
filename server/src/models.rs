use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// PublicKey DTO with numeric fields as decimal strings
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicKeyDto {
    pub n: String,
    pub e: String,
}

/// Query param for fetching multiple public keys
#[derive(Debug, Deserialize)]
pub struct PublicKeysQuery {
    /// カンマ区切り文字列を Vec<String> に変換するカスタムデシリアライザを指定
    #[serde(deserialize_with = "crate::utils::comma_separated")]
    pub names: Vec<String>,
}

/// Request body for creating a ring signature
#[derive(Debug, Deserialize)]
pub struct CreateSignatureDto {
    pub v: String,
    pub xs: Vec<String>,
    pub members: Vec<String>,
}

/// Response body for created signature ID
#[derive(Debug, Serialize)]
pub struct CreateSignatureResponse {
    pub id: Uuid,
}

/// Signature record returned to clients
#[derive(Debug, Serialize)]
pub struct SignatureRecordDto {
    pub id: Uuid,
    pub v: String,
    pub xs: Vec<String>,
    pub members: Vec<String>,
    pub created_at: DateTime<Utc>,
}
