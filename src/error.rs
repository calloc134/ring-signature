use thiserror::Error;

#[derive(Error, Debug)]
pub enum RsaError {
    #[error("modular inverse does not exist")]
    ModInv,
    #[error("e and phi are not coprime")]
    NotCoprime,
    #[error("prime generation failed")]
    PrimeGen,
    #[error("other error: {0}")]
    Other(String),
}

#[derive(Error, Debug)]
pub enum RingError {
    #[error("ring is empty")]
    EmptyRing,
    #[error("invalid signer index")]
    InvalidSignerIndex,
    #[error("other error: {0}")]
    Other(String),
}
