//! The cryptographic parameter set.
//!
//! This module provides the structure containing the cryptographic parameters required for the
//! homomorphic evaluation of Boolean circuit as well as a list of secure cryptographic parameter
//! sets.
//!
//! Two parameter sets are provided:
//!  * `tfhe::boolean::parameters::DEFAULT_PARAMETERS`
//!  * `tfhe::boolean::parameters::TFHE_LIB_PARAMETERS`
//!
//! They ensure the correctness of the Boolean circuit evaluation result (up to a certain
//! probability) along with 128-bits of security.
//!
//! The two parameter sets offer a trade-off in terms of execution time versus error probability.
//! The `DEFAULT_PARAMETERS` set offers better performances on homomorphic circuit evaluation
//! with an higher probability error in comparison with the `TFHE_LIB_PARAMETERS`.
//! Note that if you desire, you can also create your own set of parameters.
//! Failing to properly fix the parameters will potentially result with an incorrect and/or insecure
//! computation.

pub use crate::core_crypto::commons::dispersion::StandardDev;
pub use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, EncryptionKeyChoice, GlweDimension,
    LweDimension, PolynomialSize,
};

use serde::{Deserialize, Serialize};

/// A set of cryptographic parameters for homomorphic Boolean circuit evaluation.
/// The choice of encryption key for (`boolean ciphertext`)[`super::ciphertext::Ciphertext`].
///
/// * The `Big` choice means the big LWE key derived from the GLWE key is used to encrypt the input
///   ciphertext. This offers better performance but the (`public
///   key`)[`super::public_key::PublicKey`] can be extremely large and in some cases may not fit in
///   memory. When refreshing a ciphertext and/or evaluating a table lookup the PBS is computed
///   first followed by a keyswitch.
/// * The `Small` choice means the small LWE key is used to encrypt the input ciphertext.
///   Performance is not as good as in the `Big` case but (`public
///   key`)[`super::public_key::PublicKey`] sizes are much more manageable and should always fit in
///   memory. When refreshing a ciphertext and/or evaluating a table lookup the keyswitch is
///   computed first followed by a PBS.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GadgetParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_modular_std_dev: StandardDev,
    pub glwe_modular_std_dev: StandardDev,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
}

impl GadgetParameters {
    /// Constructs a new set of parameters for boolean circuit evaluation.
    ///
    /// # Warning
    ///
    /// Failing to fix the parameters properly would yield incorrect and insecure computation.
    /// Unless you are a cryptographer who really knows the impact of each of those parameters, you
    /// __must__ stick with the provided parameters [`DEFAULT_PARAMETERS`] and
    /// [`TFHE_LIB_PARAMETERS`], which both offer correct results with 128 bits of security.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        lwe_modular_std_dev: StandardDev,
        glwe_modular_std_dev: StandardDev,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        ks_level: DecompositionLevelCount,
    ) -> GadgetParameters {
        GadgetParameters {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_level,
            ks_base_log,
        }
    }
}

pub const DEFAULT_PARAMETERS: GadgetParameters = GadgetParameters {
    lwe_dimension: LweDimension(768),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000003725679281679651),
    glwe_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
};
