use crate::boolean::engine::WithThreadLocalEngine;
use crate::core_crypto::prelude::{
    lwe_ciphertext_add, lwe_ciphertext_opposite_assign, lwe_ciphertext_plaintext_add_assign,
    CiphertextModulus, LweCiphertext, Plaintext,
};
use crate::gadget::ciphertext::Ciphertext;
use crate::gadget::client_key::ClientKey;
use crate::gadget::server_key::ServerKey;
use lazy_static::lazy_static;
use std::error::Error;

use super::encoding::Encoding;
use super::engine::GadgetEngine;

pub const BOOLEAN_PARAMETERS: crate::gadget::GadgetParameters =
    crate::gadget::parameters::PLAINTEXT_2_BITS_PARAMETERS;

/// Plaintext modulus for boolean gates across all encodings is fixed to 3
static BOOLEAN_PLAINTEXT_MODULUS: u32 = 3;
static BOOLEAN_MESSAGE_TRUE: u32 = 2;
static BOOLEAN_MESSAGE_FALSE: u32 = 1;

static BOOLEAN_PLAINTEXT_TRUE: Plaintext<u32> = Plaintext(((2u64 << 32) / 3) as u32);
static BOOLEAN_PLAINTEXT_FALSE: Plaintext<u32> = Plaintext(((1u64 << 32) / 3) as u32);

lazy_static! {
    /// All boolean gates respect the following input encoding:
    /// 0 -> 1
    /// 1 -> 2
    ///
    /// For any given input wire 0 must always map to 1 and 1 must map to 2.
    ///
    /// The benefit of this encoding over naively setting [0,1] is that it -E{1} = E{0}
    /// and -E{0} = E{1}. Thus we can evaluate NOT gate without bootstrapping. Another benefit,
    /// as highligted in paper, is we switch p to 2 with PBS evalaute multiple XOR operations
    /// and switch back p to 3 for evaluating next gates. Although, the API for now ignores the
    /// latter point.
    static ref BOOLEAN_ENCODINGS: std::collections::HashMap<&'static str, Encoding> = {
        let mut encodings = std::collections::HashMap::new();

        encodings.insert(
            "and",
            Encoding::new(
                8,
                2,
                vec![BOOLEAN_MESSAGE_FALSE; 2],
                vec![BOOLEAN_MESSAGE_TRUE; 2],
                vec![0, 2],
                vec![1],
                BOOLEAN_MESSAGE_FALSE,
                BOOLEAN_MESSAGE_TRUE,
                BOOLEAN_PLAINTEXT_MODULUS,
                BOOLEAN_PLAINTEXT_MODULUS,
            ),
        );

        encodings.insert(
            "nand",
            Encoding::new(
                8,
                2,
                vec![BOOLEAN_MESSAGE_FALSE; 2],
                vec![BOOLEAN_MESSAGE_TRUE; 2],
                vec![1],
                vec![0, 2],
                BOOLEAN_MESSAGE_FALSE,
                BOOLEAN_MESSAGE_TRUE,
                BOOLEAN_PLAINTEXT_MODULUS,
                BOOLEAN_PLAINTEXT_MODULUS,
            ),
        );

        encodings.insert(
            "or",
            Encoding::new(
                8,
                2,
                vec![BOOLEAN_MESSAGE_FALSE; 2],
                vec![BOOLEAN_MESSAGE_TRUE; 2],
                vec![2],
                vec![0, 1],
                BOOLEAN_MESSAGE_FALSE,
                BOOLEAN_MESSAGE_TRUE,
                BOOLEAN_PLAINTEXT_MODULUS,
                BOOLEAN_PLAINTEXT_MODULUS,
            ),
        );

        encodings.insert(
            "nor",
            Encoding::new(
                8,
                2,
                vec![BOOLEAN_MESSAGE_FALSE; 2],
                vec![BOOLEAN_MESSAGE_TRUE; 2],
                vec![0, 1],
                vec![2],
                BOOLEAN_MESSAGE_FALSE,
                BOOLEAN_MESSAGE_TRUE,
                BOOLEAN_PLAINTEXT_MODULUS,
                BOOLEAN_PLAINTEXT_MODULUS,
            ),
        );


        encodings.insert(
            "xor",
            Encoding::new(
                8,
                2,
                vec![BOOLEAN_MESSAGE_FALSE; 2],
                vec![BOOLEAN_MESSAGE_TRUE; 2],
                vec![0],
                vec![1, 2],
                BOOLEAN_MESSAGE_FALSE,
                BOOLEAN_MESSAGE_TRUE,
                BOOLEAN_PLAINTEXT_MODULUS,
                BOOLEAN_PLAINTEXT_MODULUS,
            ),
        );


        encodings
    };
}

impl ServerKey {
    fn boolean_gate(
        &self,
        gate_str: &str,
        gate_fn: fn(lhs: bool, rhs: bool) -> bool,
        lhs: &Ciphertext,
        rhs: &Ciphertext,
    ) -> Result<Ciphertext, Box<dyn Error>> {
        let encoding = BOOLEAN_ENCODINGS.get(gate_str).unwrap();

        match (lhs, rhs) {
            (Ciphertext::Encrypted(lwe_lhs), Ciphertext::Encrypted(lwe_rhs)) => {
                let mut bootstrap_lwe_ciphertext = LweCiphertext::new(
                    0u32,
                    self.bootstrapping_key.input_lwe_dimension().to_lwe_size(),
                    CiphertextModulus::new_native(),
                );
                lwe_ciphertext_add(&mut bootstrap_lwe_ciphertext, lwe_lhs, lwe_rhs);
                self.bootstrap(Ciphertext::Encrypted(bootstrap_lwe_ciphertext), encoding)
            }
            (Ciphertext::Encrypted(lwe_lhs), Ciphertext::Trivial(trivial_rhs)) => {
                let mut bootstrap_lwe_ciphertext = lwe_lhs.clone();

                let plaintext_rhs = if *trivial_rhs {
                    BOOLEAN_PLAINTEXT_TRUE
                } else {
                    BOOLEAN_PLAINTEXT_FALSE
                };
                lwe_ciphertext_plaintext_add_assign(&mut bootstrap_lwe_ciphertext, plaintext_rhs);
                self.bootstrap(Ciphertext::Encrypted(bootstrap_lwe_ciphertext), encoding)
            }
            (Ciphertext::Trivial(trivial_lhs), Ciphertext::Encrypted(lwe_rhs)) => {
                let mut bootstrap_lwe_ciphertext = lwe_rhs.clone();

                let plaintext_rhs = if *trivial_lhs {
                    BOOLEAN_PLAINTEXT_TRUE
                } else {
                    BOOLEAN_PLAINTEXT_FALSE
                };
                lwe_ciphertext_plaintext_add_assign(&mut bootstrap_lwe_ciphertext, plaintext_rhs);
                self.bootstrap(Ciphertext::Encrypted(bootstrap_lwe_ciphertext), encoding)
            }
            (Ciphertext::Trivial(lhs), Ciphertext::Trivial(rhs)) => {
                Ok(Ciphertext::Trivial(gate_fn(*lhs, *rhs)))
            }
            _ => {
                panic!()
            }
        }
    }

    pub fn and(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext, Box<dyn Error>> {
        self.boolean_gate("and", |lhs, rhs| lhs && rhs, lhs, rhs)
    }

    pub fn nand(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext, Box<dyn Error>> {
        self.boolean_gate("nand", |lhs, rhs| !(lhs && rhs), lhs, rhs)
    }

    pub fn or(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext, Box<dyn Error>> {
        self.boolean_gate("or", |lhs, rhs| (lhs || rhs), lhs, rhs)
    }

    pub fn nor(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext, Box<dyn Error>> {
        self.boolean_gate("nor", |lhs, rhs| !(lhs || rhs), lhs, rhs)
    }

    pub fn xor(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext, Box<dyn Error>> {
        self.boolean_gate("xor", |lhs, rhs| (lhs ^ rhs), lhs, rhs)
    }

    pub fn not(&self, input: &Ciphertext) -> Ciphertext {
        match input {
            Ciphertext::Encrypted(lwe_input) => {
                let mut lwe_input_clone = lwe_input.clone();
                lwe_ciphertext_opposite_assign(&mut lwe_input_clone);
                Ciphertext::Encrypted(lwe_input_clone)
            }
            Ciphertext::Trivial(input) => Ciphertext::Trivial(!input),
            _ => {
                panic!()
            }
        }
    }
}

impl ClientKey {
    pub fn encrypt(&self, message: bool) -> Ciphertext {
        GadgetEngine::with_thread_local_mut(|engine| {
            let message = {
                if message {
                    BOOLEAN_MESSAGE_TRUE
                } else {
                    BOOLEAN_MESSAGE_FALSE
                }
            };
            engine.encrypt(message, &self, BOOLEAN_PLAINTEXT_MODULUS)
        })
    }

    pub fn decrypt(&self, ct: &Ciphertext) -> bool {
        GadgetEngine::with_thread_local_mut(|engine| {
            let message = engine.decrypt(ct, self, BOOLEAN_PLAINTEXT_MODULUS);
            if message == BOOLEAN_MESSAGE_FALSE {
                return false;
            } else if message == BOOLEAN_MESSAGE_TRUE {
                return true;
            }
            panic!("P-encoding boolean decryption returned value which isn't true nor false!")
        })
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;
    use crate::gadget::gen_keys;
    use std::error::Error;

    fn random_boolean() -> bool {
        (rand::thread_rng().gen::<u32>() % 2) != 0
    }

    #[test]
    fn test_and_gate() -> Result<(), Box<dyn Error>> {
        let (client_key, server_key) = gen_keys(&BOOLEAN_PARAMETERS);

        for _ in 0..128 {
            let lhs = random_boolean();
            let rhs = random_boolean();
            let expected_out_bool = lhs && rhs;

            let lhs_ct = client_key.encrypt(lhs);
            let rhs_ct = client_key.encrypt(rhs);
            let out_ct = server_key.and(&lhs_ct, &rhs_ct)?;
            let out_bool = client_key.decrypt(&out_ct);
            assert_eq!(out_bool, expected_out_bool, "left: {lhs}, right: {rhs}");

            // Ciphertext lhs, Trivial rhs
            let lhs_ct = client_key.encrypt(lhs);
            let out_ct = server_key.and(&lhs_ct, &Ciphertext::Trivial(rhs))?;
            let out_bool = client_key.decrypt(&out_ct);
            assert_eq!(out_bool, expected_out_bool, "left: {lhs}, right: {rhs}");

            // Trivial lhs, Ciphertext rhs
            let rhs_ct = client_key.encrypt(rhs);
            let out_ct = server_key.and(&Ciphertext::Trivial(lhs), &rhs_ct)?;
            let out_bool = client_key.decrypt(&out_ct);
            assert_eq!(out_bool, expected_out_bool, "left: {lhs}, right: {rhs}");
        }

        Ok(())
    }

    #[test]
    fn test_or_gate() -> Result<(), Box<dyn Error>> {
        let (client_key, server_key) = gen_keys(&BOOLEAN_PARAMETERS);

        for _ in 0..128 {
            let lhs = random_boolean();
            let rhs = random_boolean();
            let expected_out_bool = lhs || rhs;

            let lhs_ct = client_key.encrypt(lhs);
            let rhs_ct = client_key.encrypt(rhs);
            let out_ct = server_key.or(&lhs_ct, &rhs_ct)?;
            let out_bool = client_key.decrypt(&out_ct);
            assert_eq!(out_bool, expected_out_bool, "left: {lhs}, right: {rhs}");

            // Ciphertext lhs, Trivial rhs
            let lhs_ct = client_key.encrypt(lhs);
            let out_ct = server_key.or(&lhs_ct, &Ciphertext::Trivial(rhs))?;
            let out_bool = client_key.decrypt(&out_ct);
            assert_eq!(out_bool, expected_out_bool, "left: {lhs}, right: {rhs}");

            // Trivial lhs, Ciphertext rhs
            let rhs_ct = client_key.encrypt(rhs);
            let out_ct = server_key.or(&Ciphertext::Trivial(lhs), &rhs_ct)?;
            let out_bool = client_key.decrypt(&out_ct);
            assert_eq!(out_bool, expected_out_bool, "left: {lhs}, right: {rhs}");
        }

        Ok(())
    }

    #[test]
    fn test_and_then_or_gate() -> Result<(), Box<dyn Error>> {
        let (client_key, server_key) = gen_keys(&BOOLEAN_PARAMETERS);

        // Helps test parameters are correct for repeated bootstrapping. Even a single
        // loop should suffice.
        let mut main_wire = random_boolean();
        let mut main_wire_ct = client_key.encrypt(main_wire);
        for _ in 0..5 {
            // and
            let rhs = random_boolean();
            let rhs_ct = client_key.encrypt(rhs);
            main_wire &= rhs;
            main_wire_ct = server_key.and(&main_wire_ct, &rhs_ct)?;

            // or
            let rhs = random_boolean();
            let rhs_ct = client_key.encrypt(rhs);
            main_wire |= rhs;
            main_wire_ct = server_key.or(&main_wire_ct, &rhs_ct)?;
        }

        let out = client_key.decrypt(&main_wire_ct);
        assert_eq!(out, main_wire);

        Ok(())
    }
}
