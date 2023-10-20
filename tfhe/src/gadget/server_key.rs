use crate::boolean::engine::WithThreadLocalEngine;
use crate::core_crypto::entities::*;
use crate::gadget::client_key::ClientKey;
use crate::gadget::engine::GadgetEngine;

pub struct ServerKey {
    pub(crate) bootstrapping_key: FourierLweBootstrapKeyOwned,
    pub(crate) key_switching_key: LweKeyswitchKeyOwned<u32>,
}

impl ServerKey {
    pub fn new(client_key: &ClientKey) -> ServerKey {
        GadgetEngine::with_thread_local_mut(|engine| engine.create_server_key(client_key))
    }
}
