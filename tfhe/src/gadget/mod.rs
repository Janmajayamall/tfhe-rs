use client_key::ClientKey;
use parameters::{GadgetParameters, DEFAULT_PARAMETERS};
use server_key::ServerKey;

pub mod ciphertext;
pub mod client_key;
pub mod encoding;
pub mod engine;
pub mod parameters;
pub mod server_key;

pub fn gen_keys(parameter_set: &GadgetParameters) -> (ClientKey, ServerKey) {
    let client_key = ClientKey::new(parameter_set);
    let server_key = ServerKey::new(&client_key);
    (client_key, server_key)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use itertools::{izip, Itertools};
    use rand::{thread_rng, Rng};

    use super::ciphertext::Ciphertext;
    use super::*;

    #[test]
    fn encryption_with_odd_plaintext() -> Result<(), Box<dyn Error>> {
        let encoding: encoding::Encoding = serde_json::from_str(
            r#"
        {
            "input_mappings_1": [
                1,
                1,
                1,
                4,
                5,
                9
            ],
            "output_encodings_0": [
                0,
                1,
                2,
                3,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                14,
                15,
                16,
                17,
                19,
                20,
                21
            ],
            "output_encodings_1": [
                18,
                4,
                13
            ],
            "p": 23,
            "pin_count": 6,
            "tt_value": 176
        }
        "#,
        )?;

        let parameters = DEFAULT_PARAMETERS;
        let (client_key, server_key) = gen_keys(&parameters);

        for _ in 0..100 {
            let input = rand::thread_rng().gen::<u32>() % encoding.p;
            let ct = client_key.encrypt(input, encoding.p as u32);
            let ct_after = server_key.bootstrap(ct, &encoding).unwrap();
            let m = client_key.decrypt(&ct_after, encoding.p as u32);

            if encoding.output_encodings_0.contains(&input) {
                assert_eq!(m, 0);
            } else {
                assert_eq!(m, 1);
            }
        }

        Ok(())
    }

    #[test]
    fn evaluate_gate() -> Result<(), Box<dyn Error>> {
        let parameters = DEFAULT_PARAMETERS;
        let (client_key, server_key) = gen_keys(&parameters);

        // Encoding is for a gate with 6 inputs. tt_value is truth table of the gate with 6 inputs
        // storing output bits of each row of the truth table starting from all 0s (at LSB) and
        // ending with all 1s (at MSB). tt_value will have 2^{pin_count} bits. For ex, with 6 inputs
        // tt_value is unsgined 64 bit integer (although stored as u128)
        let encoding: encoding::Encoding = serde_json::from_str(
            r#"
        {
            "input_mappings_1": [
                1,
                3,
                20,
                5,
                18,
                10
            ],
            "output_encodings_0": [
                0,
                1,
                3,
                4,
                6,
                8,
                9,
                11,
                13,
                14,
                16,
                18,
                19,
                21,
                22
            ],
            "output_encodings_1": [
                2,
                5,
                7,
                10,
                12,
                15,
                20
            ],
            "p": 23,
            "pin_count": 6,
            "tt_value": 3120627642
        }
        "#,
        )?;

        for _ in 0..1 {
            // Iterate over each row in truth table and test correctness of output starting with all
            // 0s. Note that LSB is input to 1st pin and MSB is input to last pin
            for tt_row in 0..(1 << encoding.pin_count) {
                let mut pins = vec![];
                for i in 0..encoding.pin_count {
                    pins.push((tt_row >> i) & 1);
                }

                let input_ciphertexts = pins
                    .iter()
                    .map(|i| client_key.encrypt(*i, encoding.p as u32))
                    .collect_vec();

                let out = server_key
                    .evaluate_gate(input_ciphertexts, &encoding)
                    .unwrap();

                let output = client_key.decrypt(&out, encoding.p as u32);

                // Leaving out this piece of commented code here in case if in future there's a
                // doubt whether linear summation of ciphertexts results in
                // incorrect sum in p-encoding space or whether bootstrapping messes
                // correct summation
                //
                // result. emulate linear summation in p-encoding space
                // let mut sum_out = 0;
                // izip!(encoding.input_mappings_1.iter().rev(), pins.iter())
                //     .for_each(|(scalar, pin_in)| sum_out = ((scalar * pin_in) + sum_out) %
                // encoding.p);
                // if encoding.output_encodings_0.contains(&sum_out) {
                //     assert_eq!(output, 0);
                // } else {
                //     assert_eq!(output, 1);
                // }

                assert_eq!(output as u128, (encoding.tt_value >> tt_row as u128) & 1);
            }
        }

        Ok(())
    }

    #[test]
    fn evaluate_multiple_gates() -> Result<(), Box<dyn Error>> {
        let parameters = DEFAULT_PARAMETERS;
        let (client_key, server_key) = gen_keys(&parameters);

        // Encoding is for a gate with 6 inputs. tt_value is truth table of the gate with 6 inputs
        // storing output bits of each row of the truth table starting from all 0s (at LSB) and
        // ending with all 1s (at MSB). tt_value will have 2^{pin_count} bits. For ex, with 6 inputs
        // tt_value is unsgined 64 bit integer (although stored as u128)
        let encodings: Vec<encoding::Encoding> = serde_json::from_str(
            r#"[
                {
                    "input_mappings_1": [
                        1,
                        3,
                        20,
                        5,
                        18,
                        10
                    ],
                    "output_encodings_0": [
                        0,
                        1,
                        3,
                        4,
                        6,
                        8,
                        9,
                        11,
                        13,
                        14,
                        16,
                        18,
                        19,
                        21,
                        22
                    ],
                    "output_encodings_1": [
                        2,
                        5,
                        7,
                        10,
                        12,
                        15,
                        20
                    ],
                    "p": 23,
                    "pin_count": 6,
                    "tt_value": 3120627642
                },
                {
                    "input_mappings_1": [
                        1,
                        2,
                        21,
                        21,
                        13,
                        10
                    ],
                    "output_encodings_0": [
                        0,
                        1,
                        2,
                        3,
                        7,
                        9,
                        10,
                        11,
                        12,
                        13,
                        14,
                        15,
                        16,
                        20,
                        22
                    ],
                    "output_encodings_1": [
                        8,
                        19,
                        21,
                        6
                    ],
                    "p": 23,
                    "pin_count": 6,
                    "tt_value": 2952838064
                }
        ]"#,
        )?;

        let pin_count = encodings[0].pin_count;
        let p = encodings[0].p;

        for _ in 0..10 {
            // Iterate over each row in truth table and test correctness of output starting with all
            // 0s. Note that LSB is input to 1st pin and MSB is input to last pin

            // product 6 outputs from first gate

            let (second_gate_encrypted_inputs, second_gate_plaintext_inputs): (
                Vec<Ciphertext>,
                Vec<u32>,
            ) = (0..6)
                .into_iter()
                .map(|_| {
                    // random truth table row
                    let tt_row = thread_rng().gen::<u128>() % (1 << pin_count);

                    let mut pins = vec![];
                    for i in 0..pin_count {
                        pins.push(((tt_row >> i) & 1) as u32);
                    }

                    let input_ciphertexts = pins
                        .iter()
                        .map(|i| client_key.encrypt(*i, p as u32))
                        .collect_vec();

                    let output_ciphertext = server_key
                        .evaluate_gate(input_ciphertexts, &encodings[0])
                        .unwrap();

                    // simulate gate evaluation in plaintext
                    let mut sum_out = 0;
                    izip!(encodings[0].input_mappings_1.iter().rev(), pins.iter())
                        .for_each(|(scalar, pin_in)| sum_out = ((scalar * pin_in) + sum_out) % p);

                    let expected_bit = if encodings[0].output_encodings_0.contains(&sum_out) {
                        0u32
                    } else {
                        1u32
                    };

                    (output_ciphertext, expected_bit)
                })
                .collect_vec()
                .into_iter()
                .unzip();

            // evaluate second gate
            let encrypted_output =
                server_key.evaluate_gate(second_gate_encrypted_inputs, &encodings[1])?;

            let mut sum_out = 0;
            izip!(
                encodings[1].input_mappings_1.iter().rev(),
                second_gate_plaintext_inputs.iter()
            )
            .for_each(|(scalar, pin_in)| sum_out = ((scalar * pin_in) + sum_out) % p);

            let expected_bit = if encodings[1].output_encodings_0.contains(&sum_out) {
                0u32
            } else {
                1u32
            };

            let output_bit = client_key.decrypt(&encrypted_output, p);
            assert_eq!(expected_bit, output_bit);
        }

        Ok(())
    }
}
