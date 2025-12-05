use thiserror::Error;

// RSA関連のエラー定義
#[derive(Error, Debug)]
pub enum RsaError {
    // モジュラ逆数が存在しない
    #[error("modular inverse does not exist")]
    ModInv,
    // 公開指数 e と φ(n) が互いに素でない
    #[error("e and phi are not coprime")]
    NotCoprime,
    // 素数生成に失敗
    #[error("prime generation failed")]
    PrimeGen,
    // 不正な公開指数（Carmichael鍵攻撃対策）
    #[error("invalid public exponent: expected 65537, got {actual}. Non-standard exponents may indicate a malicious key (Carmichael key attack).")]
    InvalidPublicExponent { actual: String },
    // その他のエラー
    #[error("other error: {0}")]
    Other(String),
}

// リング署名関連のエラー定義
#[derive(Error, Debug)]
pub enum RingError {
    // リングが空
    #[error("ring is empty")]
    EmptyRing,
    // 署名者のインデックスが無効
    #[error("invalid signer index")]
    InvalidSignerIndex,
    // その他のエラー
    #[error("other error: {0}")]
    Other(String),
}
