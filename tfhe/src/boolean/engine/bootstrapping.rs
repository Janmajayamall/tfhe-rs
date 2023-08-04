use crate::boolean::ciphertext::Ciphertext;
use crate::boolean::{ClientKey, PLAINTEXT_TRUE};
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::generators::{DeterministicSeeder, EncryptionRandomGenerator};
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, Seeder};
use crate::core_crypto::commons::parameters::{CiphertextModulus, PBSOrder};
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::math::fft::Fft;
use serde::{Deserialize, Serialize};
use std::error::Error;

/// Memory used as buffer for the bootstrap
///
/// It contains contiguous chunk which is then sliced and converted
/// into core's View types.
#[derive(Default)]
struct Memory {
    buffer: Vec<u32>,
}

pub struct BuffersRef<'a> {
    pub(crate) lookup_table: GlweCiphertextMutView<'a, u32>,
    // For the intermediate keyswitch result in the case of a big ciphertext
    pub(crate) buffer_lwe_after_ks: LweCiphertextMutView<'a, u32>,
    // For the intermediate PBS result in the case of a smallciphertext
    pub(crate) buffer_lwe_after_pbs: LweCiphertextMutView<'a, u32>,
}

impl Memory {
    fn as_buffers(&mut self, server_key: &ServerKey) -> BuffersRef<'_> {
        let num_elem_in_accumulator = server_key.bootstrapping_key.glwe_size().0
            * server_key.bootstrapping_key.polynomial_size().0;
        let num_elem_in_lwe_after_ks = server_key.key_switching_key.output_lwe_size().0;
        let num_elem_in_lwe_after_pbs = server_key
            .bootstrapping_key
            .output_lwe_dimension()
            .to_lwe_size()
            .0;

        let total_elem_needed =
            num_elem_in_accumulator + num_elem_in_lwe_after_ks + num_elem_in_lwe_after_pbs;

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

        acc.get_mut_mask().as_mut().fill(0u32);
        acc.get_mut_body().as_mut().fill(PLAINTEXT_TRUE);

        let (after_ks_elements, after_pbs_elements) =
            other_elements.split_at_mut(num_elem_in_lwe_after_ks);

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

/// A structure containing the server public key.
///
/// This server key data lives on the CPU.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic Boolean circuits.
///
/// In more details, it contains:
/// * `bootstrapping_key` - a public key, used to perform the bootstrapping operation.
/// * `key_switching_key` - a public key, used to perform the key-switching operation.
#[derive(Clone, Serialize, Deserialize)]
pub struct ServerKey {
    pub(crate) bootstrapping_key: FourierLweBootstrapKeyOwned,
    pub(crate) key_switching_key: LweKeyswitchKeyOwned<u32>,
    pub(crate) pbs_order: PBSOrder,
}

impl ServerKey {
    pub fn bootstrapping_key_size_elements(&self) -> usize {
        self.bootstrapping_key.as_view().data().as_ref().len()
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        std::mem::size_of_val(self.bootstrapping_key.as_view().data())
    }

    pub fn key_switching_key_size_elements(&self) -> usize {
        self.key_switching_key.as_ref().len()
    }

    pub fn key_switching_key_size_bytes(&self) -> usize {
        std::mem::size_of_val(self.key_switching_key.as_ref())
    }
}

/// A structure containing the compressed server public key.
///
/// This server key data lives on the CPU.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic Boolean circuits.
///
/// In more details, it contains:
/// * `bootstrapping_key` - a public key, used to perform the bootstrapping operation.
/// * `key_switching_key` - a public key, used to perform the key-switching operation.
#[derive(Clone, Serialize, Deserialize)]
pub struct CompressedServerKey {
    pub(crate) bootstrapping_key: SeededLweBootstrapKeyOwned<u32>,
    pub(crate) key_switching_key: SeededLweKeyswitchKeyOwned<u32>,
    pub(crate) pbs_order: PBSOrder,
}

/// Perform ciphertext bootstraps on the CPU
pub(crate) struct Bootstrapper {
    memory: Memory,
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`EncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    pub(crate) encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
    pub(crate) computation_buffers: ComputationBuffers,
    pub(crate) seeder: DeterministicSeeder<ActivatedRandomGenerator>,
}

impl Bootstrapper {
    pub fn new(seeder: &mut dyn Seeder) -> Self {
        Bootstrapper {
            memory: Default::default(),
            encryption_generator: EncryptionRandomGenerator::<_>::new(seeder.seed(), seeder),
            computation_buffers: Default::default(),
            seeder: DeterministicSeeder::<_>::new(seeder.seed()),
        }
    }

    pub(crate) fn new_server_key(
        &mut self,
        cks: &ClientKey,
    ) -> Result<ServerKey, Box<dyn std::error::Error>> {
        let standard_bootstraping_key: LweBootstrapKeyOwned<u32> =
            par_allocate_and_generate_new_lwe_bootstrap_key(
                &cks.lwe_secret_key,
                &cks.glwe_secret_key,
                cks.parameters.pbs_base_log,
                cks.parameters.pbs_level,
                cks.parameters.glwe_modular_std_dev,
                CiphertextModulus::new_native(),
                &mut self.encryption_generator,
            );

        // creation of the bootstrapping key in the Fourier domain
        let mut fourier_bsk = FourierLweBootstrapKey::new(
            standard_bootstraping_key.input_lwe_dimension(),
            standard_bootstraping_key.glwe_size(),
            standard_bootstraping_key.polynomial_size(),
            standard_bootstraping_key.decomposition_base_log(),
            standard_bootstraping_key.decomposition_level_count(),
        );

        let fft = Fft::new(standard_bootstraping_key.polynomial_size());
        let fft = fft.as_view();
        self.computation_buffers.resize(
            convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();

        // Conversion to fourier domain
        convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized(
            &standard_bootstraping_key,
            &mut fourier_bsk,
            fft,
            stack,
        );

        // Convert the GLWE secret key into an LWE secret key:
        let big_lwe_secret_key = cks.glwe_secret_key.clone().into_lwe_secret_key();

        // creation of the key switching key
        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &big_lwe_secret_key,
            &cks.lwe_secret_key,
            cks.parameters.ks_base_log,
            cks.parameters.ks_level,
            cks.parameters.lwe_modular_std_dev,
            CiphertextModulus::new_native(),
            &mut self.encryption_generator,
        );

        Ok(ServerKey {
            bootstrapping_key: fourier_bsk,
            key_switching_key: ksk,
            pbs_order: cks.parameters.encryption_key_choice.into(),
        })
    }

    pub(crate) fn new_compressed_server_key(
        &mut self,
        cks: &ClientKey,
    ) -> Result<CompressedServerKey, Box<dyn std::error::Error>> {
        #[cfg(not(feature = "__wasm_api"))]
        let bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
            &cks.lwe_secret_key,
            &cks.glwe_secret_key,
            cks.parameters.pbs_base_log,
            cks.parameters.pbs_level,
            cks.parameters.glwe_modular_std_dev,
            CiphertextModulus::new_native(),
            &mut self.seeder,
        );

        #[cfg(feature = "__wasm_api")]
        let bootstrapping_key = allocate_and_generate_new_seeded_lwe_bootstrap_key(
            &cks.lwe_secret_key,
            &cks.glwe_secret_key,
            cks.parameters.pbs_base_log,
            cks.parameters.pbs_level,
            cks.parameters.glwe_modular_std_dev,
            CiphertextModulus::new_native(),
            &mut self.seeder,
        );

        let big_lwe_secret_key = cks.glwe_secret_key.clone().into_lwe_secret_key();

        // creation of the key switching key
        let key_switching_key = allocate_and_generate_new_seeded_lwe_keyswitch_key(
            &big_lwe_secret_key,
            &cks.lwe_secret_key,
            cks.parameters.ks_base_log,
            cks.parameters.ks_level,
            cks.parameters.lwe_modular_std_dev,
            CiphertextModulus::new_native(),
            &mut self.seeder,
        );

        Ok(CompressedServerKey {
            bootstrapping_key,
            key_switching_key,
            pbs_order: cks.parameters.encryption_key_choice.into(),
        })
    }

    pub(crate) fn bootstrap(
        &mut self,
        input: &LweCiphertextOwned<u32>,
        server_key: &ServerKey,
    ) -> Result<LweCiphertextOwned<u32>, Box<dyn Error>> {
        let BuffersRef {
            lookup_table: accumulator,
            mut buffer_lwe_after_pbs,
            ..
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
            input,
            &mut buffer_lwe_after_pbs,
            &accumulator,
            fourier_bsk,
            fft,
            stack,
        );

        Ok(LweCiphertext::from_container(
            buffer_lwe_after_pbs.as_ref().to_owned(),
            input.ciphertext_modulus(),
        ))
    }

    pub(crate) fn keyswitch(
        &mut self,
        input: &LweCiphertextOwned<u32>,
        server_key: &ServerKey,
    ) -> Result<LweCiphertextOwned<u32>, Box<dyn Error>> {
        // Allocate the output of the KS
        let mut output = LweCiphertext::new(
            0u32,
            server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
            input.ciphertext_modulus(),
        );

        keyswitch_lwe_ciphertext(&server_key.key_switching_key, input, &mut output);

        Ok(output)
    }

    pub(crate) fn bootstrap_keyswitch(
        &mut self,
        mut ciphertext: LweCiphertextOwned<u32>,
        server_key: &ServerKey,
    ) -> Result<Ciphertext, Box<dyn Error>> {
        let BuffersRef {
            lookup_table,
            mut buffer_lwe_after_pbs,
            ..
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

        // Compute a bootstrap
        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            &ciphertext,
            &mut buffer_lwe_after_pbs,
            &lookup_table,
            fourier_bsk,
            fft,
            stack,
        );

        // Compute a key switch to get back to input key
        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &buffer_lwe_after_pbs,
            &mut ciphertext,
        );

        Ok(Ciphertext::Encrypted(ciphertext))
    }

    pub(crate) fn keyswitch_bootstrap(
        &mut self,
        mut ciphertext: LweCiphertextOwned<u32>,
        server_key: &ServerKey,
    ) -> Result<Ciphertext, Box<dyn Error>> {
        let BuffersRef {
            lookup_table,
            mut buffer_lwe_after_ks,
            ..
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

        // Keyswitch from large LWE key to the small one
        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &ciphertext,
            &mut buffer_lwe_after_ks,
        );

        // Compute a bootstrap
        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            &buffer_lwe_after_ks,
            &mut ciphertext,
            &lookup_table,
            fourier_bsk,
            fft,
            stack,
        );

        Ok(Ciphertext::Encrypted(ciphertext))
    }
    pub(crate) fn apply_bootstrapping_pattern(
        &mut self,
        ct: LweCiphertextOwned<u32>,
        server_key: &ServerKey,
    ) -> Result<Ciphertext, Box<dyn Error>> {
        match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.keyswitch_bootstrap(ct, server_key),
            PBSOrder::BootstrapKeyswitch => self.bootstrap_keyswitch(ct, server_key),
        }
    }
}

impl From<CompressedServerKey> for ServerKey {
    fn from(compressed_server_key: CompressedServerKey) -> Self {
        let CompressedServerKey {
            key_switching_key,
            bootstrapping_key,
            pbs_order,
        } = compressed_server_key;

        let key_switching_key = key_switching_key.decompress_into_lwe_keyswitch_key();
        let standard_bootstrapping_key = bootstrapping_key.decompress_into_lwe_bootstrap_key();

        let mut bootstrapping_key = FourierLweBootstrapKeyOwned::new(
            standard_bootstrapping_key.input_lwe_dimension(),
            standard_bootstrapping_key.glwe_size(),
            standard_bootstrapping_key.polynomial_size(),
            standard_bootstrapping_key.decomposition_base_log(),
            standard_bootstrapping_key.decomposition_level_count(),
        );

        convert_standard_lwe_bootstrap_key_to_fourier(
            &standard_bootstrapping_key,
            &mut bootstrapping_key,
        );

        Self {
            key_switching_key,
            bootstrapping_key,
            pbs_order,
        }
    }
}
