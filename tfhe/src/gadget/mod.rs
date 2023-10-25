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
    use itertools::{izip, Itertools};
    use rand::Rng;

    use super::*;

    #[test]
    fn encryption_with_odd_plaintext() {
        let encoding = encoding::Encoding {
            tt_value: 4294836227,
            pin_count: 6,
            p: 23,
            input_mappings_1: vec![1, 2, 3, 3, 3, 11],
            output_encodings_0: vec![0, 1, 2, 3, 4, 6, 7, 9, 10, 12, 14, 15, 17, 18, 20, 21],
            output_encodings_1: vec![5, 8, 11, 13, 16, 19, 22],
        };
        let parameters = DEFAULT_PARAMETERS;
        let (client_key, server_key) = gen_keys(&parameters);

        for _ in 0..100 {
            let input = rand::thread_rng().gen::<u32>() % encoding.p;
            let ct = client_key.encrypt(input, &encoding);
            let ct_after = server_key.bootstrap(ct, &encoding).unwrap();
            let m = client_key.decrypt(&ct_after, &encoding);

            if encoding.output_encodings_0.contains(&input) {
                assert_eq!(m, 0);
            } else {
                assert_eq!(m, 1);
            }
        }
    }

    #[test]
    fn evaluate_gate() {
        let parameters = DEFAULT_PARAMETERS;
        let (client_key, server_key) = gen_keys(&parameters);

        // Encoding is for a gate with 6 inputs. tt_value is truth table of the gate with 6 inputs
        // storing output bits of each row of the truth table starting from all 0s (at LSB) and
        // ending with all 1s (at MSB). tt_value will have 2^{pin_count} bits. For ex, with 6 inputs
        // tt_value is unsgined 64 bit integer (although stored as u128)
        let encoding = encoding::Encoding {
            tt_value: 4294836226,
            pin_count: 6,
            p: 23,
            input_mappings_1: vec![1, 2, 3, 3, 3, 11],
            output_encodings_0: vec![0, 1, 2, 3, 4, 6, 7, 9, 10, 12, 14, 15, 17, 18, 20, 21],
            output_encodings_1: vec![5, 8, 11, 13, 16, 19, 22],
        };

        // Iterate over each row in truth table and test correctness of output starting with all 0s.
        // Note that LSB is input to 1st pin and MSB is input to last pin
        for tt_row in 0..(1 << encoding.pin_count) {
            let mut pins = vec![];
            for i in 0..encoding.pin_count {
                pins.push((tt_row >> i) & 1);
            }

            let input_ciphertexts = pins
                .iter()
                .map(|i| client_key.encrypt(*i, &encoding))
                .collect_vec();

            let out = server_key
                .evaluate_gate(&input_ciphertexts, &encoding)
                .unwrap();

            let output = client_key.decrypt(&out, &encoding);

            // Leaving out this piece of commented code here in case if in future there's a doubt
            // whether linear summation of ciphertexts results in incorrect sum in
            // p-encoding space or whether bootstrapping messes correct summation
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
}
