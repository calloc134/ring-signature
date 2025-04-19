pub mod constants;
pub mod crypto_utils;
pub mod error;
pub mod ring;
pub mod rsa;

// Re-export for external use (PGP loaders instead of PEM)
pub use constants::*;
pub use crypto_utils::{d_k, e_k};
pub use error::{RingError, RsaError};
pub use ring::{ring_sign, ring_verify, RingSignature};
pub use rsa::{
    generate_keypair, load_keypair_from_pgp, load_public_key_from_pgp, rsa_sign, rsa_verify,
    KeyPair, PublicKey, SecretKey,
};
