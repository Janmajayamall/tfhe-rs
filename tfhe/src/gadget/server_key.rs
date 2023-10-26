use crate::boolean::engine::WithThreadLocalEngine;
use crate::core_crypto::entities::*;
use crate::gadget::ciphertext::Ciphertext;
use crate::gadget::client_key::ClientKey;
use crate::gadget::engine::GadgetEngine;
use std::error::Error;

use super::encoding::Encoding;

pub struct ServerKey {
    pub(crate) bootstrapping_key: FourierLweBootstrapKeyOwned,
    pub(crate) key_switching_key: LweKeyswitchKeyOwned<u32>,
}

impl ServerKey {
    pub fn new(client_key: &ClientKey) -> ServerKey {
        GadgetEngine::with_thread_local_mut(|engine| engine.create_server_key(client_key))
    }

    pub fn bootstrap(
        &self,
        ct: Ciphertext,
        encoding: &Encoding,
    ) -> Result<Ciphertext, Box<dyn Error>> {
        GadgetEngine::with_thread_local_mut(|engine| engine.bootstrap(ct, &self, encoding))
    }

    pub fn evaluate_gate(
        &self,
        input_ciphertexts: Vec<Ciphertext>,
        encoding: &Encoding,
    ) -> Result<Ciphertext, Box<dyn Error>> {
        GadgetEngine::with_thread_local_mut(|engine| {
            engine.evaluate_gate(&self, encoding, input_ciphertexts)
        })
    }
}
