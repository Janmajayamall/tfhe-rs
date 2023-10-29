//! The secret key of the client.
//!
//! This module implements the generation of the client' secret keys, together with the
//! encryption and decryption methods.

use crate::boolean::engine::WithThreadLocalEngine;
use crate::core_crypto::entities::*;
use crate::gadget::ciphertext::Ciphertext;
use crate::gadget::engine::GadgetEngine;
use crate::gadget::parameters::GadgetParameters;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};

use super::encoding::{self, Encoding};

/// A structure containing the client key, which must be kept secret.
///
/// In more details, it contains:
/// * `lwe_secret_key` - an LWE secret key, used to encrypt the inputs and decrypt the outputs.
/// This secret key is also used in the generation of bootstrapping and key switching keys.
/// * `glwe_secret_key` - a GLWE secret key, used to generate the bootstrapping keys and key
/// switching keys.
/// * `parameters` - the cryptographic parameter set.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientKey {
    pub(crate) lwe_secret_key: LweSecretKeyOwned<u32>,
    pub(crate) glwe_secret_key: GlweSecretKeyOwned<u32>,
    pub(crate) parameters: GadgetParameters,
}

impl PartialEq for ClientKey {
    fn eq(&self, other: &Self) -> bool {
        self.parameters == other.parameters
            && self.lwe_secret_key == other.lwe_secret_key
            && self.glwe_secret_key == other.glwe_secret_key
    }
}

impl Debug for ClientKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientKey {{ ")?;
        write!(f, "lwe_secret_key: {:?}, ", self.lwe_secret_key)?;
        write!(f, "glwe_secret_key: {:?}, ", self.glwe_secret_key)?;
        write!(f, "parameters: {:?}, ", self.parameters)?;
        write!(f, "engine: CoreEngine, ")?;
        write!(f, "}}")?;
        Ok(())
    }
}

impl ClientKey {
    pub fn new(parameter_set: &GadgetParameters) -> ClientKey {
        GadgetEngine::with_thread_local_mut(|engine| engine.create_client_key(parameter_set))
    }
}
