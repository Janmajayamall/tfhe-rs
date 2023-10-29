use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Encoding {
    // we actually don't use this value anywhere in rust
    pub(crate) tt_value: u128,
    pub(crate) pin_count: usize,
    /// Input pin mappings when pin is set to 1. Mapping when pin is set to 0 defaults to 0.
    /// Given a gate with input pins a, b, c (i.e. starting with LSB), pins are mapped to:
    /// a, b, c => c, b, a (i.e. in reverse) as a row in truth table.
    pub(crate) input_mappings_0: Vec<u32>,
    pub(crate) input_mappings_1: Vec<u32>,
    pub(crate) output_encodings_0: Vec<u32>,
    pub(crate) output_encodings_1: Vec<u32>,
    pub(crate) new_0: u32,
    pub(crate) new_1: u32,
    pub(crate) p: u32,
    pub(crate) new_p: u32,
}

impl Encoding {
    pub fn new(
        tt_value: u128,
        pin_count: usize,
        input_mappings_0: Vec<u32>,
        input_mappings_1: Vec<u32>,
        output_encodings_0: Vec<u32>,
        output_encodings_1: Vec<u32>,
        new_0: u32,
        new_1: u32,
        p: u32,
        new_p: u32,
    ) -> Encoding {
        Encoding {
            tt_value,
            pin_count,
            input_mappings_0,
            input_mappings_1,
            output_encodings_0,
            output_encodings_1,
            new_0,
            new_1,
            p,
            new_p,
        }
    }

    pub fn new_canonical(
        tt_value: u128,
        pin_count: usize,
        input_mappings_1: Vec<u32>,
        output_encodings_0: Vec<u32>,
        output_encodings_1: Vec<u32>,
        p: u32,
    ) -> Encoding {
        let input_mappings_0 = vec![0u32; pin_count];
        Self::new(
            tt_value,
            pin_count,
            input_mappings_0,
            input_mappings_1,
            output_encodings_0,
            output_encodings_1,
            0,
            1,
            p,
            p,
        )
    }

    pub fn create_accumulator(&self) -> Vec<u32> {
        let p = self.p as usize;

        // p+1 to accomodate other half window corresponding to 0
        let mut acc = vec![0; p + 1];

        let new_0 = self.new_0;
        let new_1 = self.new_1;
        for i in 0..((p + 1) / 2) {
            // first half
            let alpha = i;
            if self.output_encodings_0.contains(&(alpha as u32)) {
                acc[2 * i] = new_0;
            } else {
                acc[2 * i] = new_1;
            }

            let beta = (alpha + ((p + 1) / 2)) % p;
            if self.output_encodings_0.contains(&(beta as u32)) {
                acc[2 * i + 1] = (self.new_p - new_0) % self.new_p as u32;
            } else {
                acc[2 * i + 1] = (self.new_p - new_1) % self.new_p as u32;
            }
        }

        acc
    }

    pub fn tt_value(&self) -> u128 {
        self.tt_value
    }

    pub fn p(&self) -> u32 {
        self.p
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn print_accumulator() {
        let encoding = Encoding::new_canonical(
            4294836226,
            6,
            vec![1, 2, 3, 3, 3, 11],
            vec![0, 1, 2, 3, 4, 6, 7, 9, 10, 12, 14, 15, 17, 18, 20, 21],
            vec![5, 8, 11, 13, 16, 19, 22],
            23,
        );
        let acc = encoding.create_accumulator();
        println!("Acc: {:?}", acc);
    }

    #[test]
    fn deserialization_works() -> Result<(), Box<dyn Error>> {
        let json_data = r#"
        [{
            "input_mappings_1": [
                1,
                1,
                1,
                1,
                5,
                6
            ],
            "output_encodings_0": [
                0,
                1,
                2,
                3,
                4,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15
            ],
            "output_encodings_1": [
                5
            ],
            "p": 23,
            "pin_count": 6,
            "tt_value": 4
        },{
            "input_mappings_1": [
                1,
                1,
                1,
                1,
                5,
                5
            ],
            "output_encodings_0": [
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                11,
                12,
                13,
                14
            ],
            "output_encodings_1": [
                10
            ],
            "p": 23,
            "pin_count": 6,
            "tt_value": 8
        },{
            "input_mappings_1": [
                1,
                2,
                2,
                2,
                2,
                2
            ],
            "output_encodings_0": [
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                11
            ],
            "output_encodings_1": [
                10
            ],
            "p": 23,
            "pin_count": 6,
            "tt_value": 2147483648
        },{
            "input_mappings_1": [
                1,
                2,
                2,
                2,
                2,
                9
            ],
            "output_encodings_0": [
                0,
                1,
                2,
                4,
                6,
                8,
                11,
                13,
                15,
                17
            ],
            "output_encodings_1": [
                3,
                5,
                7,
                9,
                10,
                12,
                14,
                16,
                18
            ],
            "p": 23,
            "pin_count": 6,
            "tt_value": 18446744065119617026
        }]
        "#;
        let encodings: Vec<Encoding> = serde_json::from_str(json_data)?;
        Ok(())
    }
}
