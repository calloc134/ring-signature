use serde::{Deserialize, Serialize};

/// Structure for CLI signature input/output via JSON
#[derive(Debug, Serialize, Deserialize)]
pub struct CliSignaturePayload {
    /// Ring signature glue value (hex string)
    pub v: String,
    /// Ring signature contribution values (hex strings)
    pub xs: Vec<String>,
    /// Original message signed
    pub message: String,
}
