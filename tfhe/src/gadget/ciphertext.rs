use crate::core_crypto::entities::*;
use serde::{Deserialize, Serialize};

/// A structure containing a ciphertext, meant to encrypt a Boolean message.
///
/// It is used to evaluate a Boolean circuits homomorphically.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Ciphertext {
    Encrypted(LweCiphertextOwned<u32>),
    Trivial(bool),
}

//TODO: add seeded ciphertext
