use concrete_csprng::seeders::Seeder;

use crate::boolean::engine::WithThreadLocalEngine;
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::commons::parameters::CiphertextModulus;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{
    allocate_and_encrypt_new_lwe_ciphertext, allocate_and_generate_new_binary_glwe_secret_key,
    allocate_and_generate_new_binary_lwe_secret_key, allocate_and_generate_new_lwe_keyswitch_key,
    convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement,
    decrypt_lwe_ciphertext, keyswitch_lwe_ciphertext, new_seeder,
    par_allocate_and_generate_new_lwe_bootstrap_key,
    par_convert_standard_lwe_bootstrap_key_to_fourier,
    programmable_bootstrap_lwe_ciphertext_mem_optimized,
    programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement, ActivatedRandomGenerator,
    ComputationBuffers, EncryptionRandomGenerator, Fft, FourierLweBootstrapKey,
    FourierLweBootstrapKeyOwned, GlweCiphertext, LweCiphertextMutView, LweKeyswitchKeyOwned,
    SecretRandomGenerator,
};
use crate::gadget::ciphertext::Ciphertext;
use crate::gadget::client_key::ClientKey;
use crate::gadget::parameters::GadgetParameters;
use crate::gadget::server_key::ServerKey;
use std::cell::RefCell;
use std::error::Error;
use std::thread_local;

struct Encoding {
    p: u32,
}

pub struct BuffersRef<'a> {
    pub(crate) lookup_table: GlweCiphertextMutView<'a, u32>,
    // For the intermediate keyswitch result in the case of a big ciphertext
    pub(crate) buffer_lwe_after_ks: LweCiphertextMutView<'a, u32>,
    // For the intermediate PBS result in the case of a smallciphertext
    pub(crate) buffer_lwe_after_pbs: LweCiphertextMutView<'a, u32>,
}

#[derive(Default)]
struct Memory {
    buffer: Vec<u32>,
}

impl Memory {
    fn as_buffers(&mut self, server_key: &ServerKey) -> BuffersRef<'_> {
        let num_elem_in_accumulator = server_key.bootstrapping_key.glwe_size().0
            * server_key.bootstrapping_key.polynomial_size().0;
        let num_of_elem_lwe_after_ksk = server_key.key_switching_key.output_lwe_size().0;
        let num_of_elem_lwe_after_pbs = server_key.bootstrapping_key.output_lwe_dimension().0;

        let total_elem_needed =
            num_elem_in_accumulator + num_of_elem_lwe_after_ksk + num_of_elem_lwe_after_pbs;

        let all_elements = if self.buffer.len() < total_elem_needed {
            self.buffer.resize(total_elem_needed, 0u32);
            self.buffer.as_mut_slice()
        } else {
            &mut self.buffer[..total_elem_needed]
        };

        let (accumulator_elements, other_elements) =
            all_elements.split_at_mut(num_elem_in_accumulator);

        let mut acc = GlweCiphertext::from_container(
            accumulator_elements,
            server_key.bootstrapping_key.polynomial_size(),
            CiphertextModulus::new_native(),
        );

        // accumulator is a trivial ciphertext of test vector polynomial
        acc.get_mut_mask().as_mut().fill(0u32);
        // set test vector to all 1s; asssume p = 2^4
        acc.get_mut_body().as_mut().fill(1 << 28);

        let (after_ks_elements, after_pbs_elements) =
            other_elements.split_at_mut(num_of_elem_lwe_after_ksk);

        let buffer_lwe_after_ks = LweCiphertextMutView::from_container(
            after_ks_elements,
            CiphertextModulus::new_native(),
        );
        let buffer_lwe_after_pbs = LweCiphertextMutView::from_container(
            after_pbs_elements,
            CiphertextModulus::new_native(),
        );

        BuffersRef {
            lookup_table: acc,
            buffer_lwe_after_ks,
            buffer_lwe_after_pbs,
        }
    }
}

pub struct Bootstrapper {
    memory: Memory,

    encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
    computation_buffers: ComputationBuffers,
}

impl Bootstrapper {
    pub fn new(seeder: &mut dyn Seeder) -> Self {
        let memory = Default::default();

        Bootstrapper {
            memory,
            encryption_generator: EncryptionRandomGenerator::<_>::new(seeder.seed(), seeder),
            computation_buffers: ComputationBuffers::default(),
        }
    }

    pub fn bootstrap_keyswitch(
        &mut self,
        mut ciphertext: LweCiphertextOwned<u32>,
        server_key: &ServerKey,
    ) -> Result<Ciphertext, Box<dyn Error>> {
        let BuffersRef {
            lookup_table: accumulator,
            mut buffer_lwe_after_pbs,
            mut buffer_lwe_after_ks,
        } = self.memory.as_buffers(server_key);

        let fourier_bsk = &server_key.bootstrapping_key;

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        self.computation_buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();

        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            &ciphertext,
            &mut buffer_lwe_after_pbs,
            &accumulator,
            fourier_bsk,
            fft,
            stack,
        );

        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &buffer_lwe_after_pbs,
            &mut ciphertext,
        );

        Ok(Ciphertext::Encrypted(ciphertext))
    }

    pub fn new_server_key(&mut self, client_key: &ClientKey) -> ServerKey {
        let bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
            &client_key.lwe_secret_key,
            &client_key.glwe_secret_key,
            client_key.parameters.pbs_base_log,
            client_key.parameters.pbs_level,
            client_key.parameters.glwe_modular_std_dev,
            CiphertextModulus::new_native(),
            &mut self.encryption_generator,
        );

        // convert to fourier domain
        let mut fourier_bsk = FourierLweBootstrapKey::new(
            bootstrapping_key.input_lwe_dimension(),
            bootstrapping_key.glwe_size(),
            bootstrapping_key.polynomial_size(),
            bootstrapping_key.decomposition_base_log(),
            bootstrapping_key.decomposition_level_count(),
        );

        let fft = Fft::new(bootstrapping_key.polynomial_size());
        let fft = fft.as_view();
        self.computation_buffers.resize(
            convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );

        par_convert_standard_lwe_bootstrap_key_to_fourier(&bootstrapping_key, &mut fourier_bsk);

        let big_lwe_secret_key = client_key.glwe_secret_key.clone().into_lwe_secret_key();

        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &big_lwe_secret_key,
            &client_key.lwe_secret_key,
            client_key.parameters.ks_base_log,
            client_key.parameters.ks_level,
            client_key.parameters.lwe_modular_std_dev,
            CiphertextModulus::new_native(),
            &mut self.encryption_generator,
        );

        ServerKey {
            bootstrapping_key: fourier_bsk,
            key_switching_key: ksk,
        }
    }
}

thread_local! {
    static GADGET_ENGINE: RefCell<GadgetEngine> = RefCell::new(GadgetEngine::new());
}

pub struct GadgetEngine {
    bootstrapper: Bootstrapper,
    secret_generator: SecretRandomGenerator<ActivatedRandomGenerator>,
    encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
}

impl WithThreadLocalEngine for GadgetEngine {
    fn with_thread_local_mut<R, F>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        GADGET_ENGINE.with(|engine| func(&mut engine.borrow_mut()))
    }
}

impl GadgetEngine {
    pub fn new() -> Self {
        let mut root_seeder = new_seeder();
        Self::new_from_seeder(root_seeder.as_mut())
    }

    pub fn new_from_seeder(root_seeder: &mut dyn Seeder) -> Self {
        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(root_seeder.seed());

        // Note that the operands are evaluated from left to right for Rust Struct expressions
        // See: https://doc.rust-lang.org/stable/reference/expressions.html?highlight=left#evaluation-order-of-operands
        Self {
            secret_generator: SecretRandomGenerator::<_>::new(deterministic_seeder.seed()),
            encryption_generator: EncryptionRandomGenerator::<_>::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            ),
            bootstrapper: Bootstrapper::new(&mut deterministic_seeder),
        }
    }

    pub fn encrypt(&mut self, message: u32, client_key: &ClientKey) -> Ciphertext {
        // TODO: implement encoding
        // For now message simply insert message in top 4 bits
        let plaintext = Plaintext((message % 16) << 28);

        // default to small LWE secret
        let lwe_secret = LweSecretKey::from_container(client_key.lwe_secret_key.as_ref());

        let ct = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_secret,
            plaintext,
            client_key.parameters.lwe_modular_std_dev,
            CiphertextModulus::new_native(),
            &mut self.encryption_generator,
        );

        Ciphertext::Encrypted(ct)
    }

    pub fn decrypt(&self, ct: &Ciphertext, client_key: &ClientKey) -> u32 {
        match ct {
            Ciphertext::Encrypted(lwe_ct) => {
                // default to small LWE secret
                let lwe_secret = LweSecretKey::from_container(client_key.lwe_secret_key.as_ref());

                let decrypted_u32 = decrypt_lwe_ciphertext(&lwe_secret, &lwe_ct);

                // assume p = 2^4
                (decrypted_u32.0 >> 28) % 16
            }
            Ciphertext::Trivial(b) => *b,
        }
    }

    pub fn create_server_key(&mut self, client_key: &ClientKey) -> ServerKey {
        self.bootstrapper.new_server_key(client_key)
    }

    pub fn create_client_key(&mut self, parameters: &GadgetParameters) -> ClientKey {
        let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            parameters.lwe_dimension,
            &mut self.secret_generator,
        );

        let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            parameters.glwe_dimension,
            parameters.polynomial_size,
            &mut self.secret_generator,
        );

        ClientKey {
            lwe_secret_key,
            glwe_secret_key,
            parameters: parameters.clone(),
        }
    }
}
