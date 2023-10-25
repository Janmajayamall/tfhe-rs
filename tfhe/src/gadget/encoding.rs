pub struct Encoding {
    // we actually don't use this value anywhere in rust
    pub(crate) tt_value: u128,
    pub(crate) pin_count: usize,
    /// Input pin mappings when pin is set to 1. Mapping when pin is set to 0 defaults to 0.
    /// Given a gate with input pins a, b, c (i.e. starting with LSB), pins are mapped to:
    /// a, b, c => c, b, a (i.e. in reverse) as a row in truth table.
    pub(crate) input_mappings_1: Vec<u32>,
    pub(crate) output_encodings_0: Vec<u32>,
    pub(crate) output_encodings_1: Vec<u32>,
    pub(crate) p: u32,
}

impl Encoding {
    pub fn new(
        tt_value: u128,
        pin_count: usize,
        input_mappings_1: Vec<u32>,
        output_encodings_0: Vec<u32>,
        output_encodings_1: Vec<u32>,
        p: u32,
    ) -> Encoding {
        Encoding {
            tt_value,
            pin_count,
            input_mappings_1,
            output_encodings_0,
            output_encodings_1,
            p,
        }
    }

    pub fn create_accumulator(&self) -> Vec<u32> {
        let p = self.p as usize;

        // p+1 to accomodate other half window corresponding to 0
        let mut acc = vec![0; p + 1];

        let map_to_0 = 0;
        let map_to_1 = 1;
        for i in 0..((p + 1) / 2) {
            // first half
            let alpha = i;
            if self.output_encodings_0.contains(&(alpha as u32)) {
                acc[2 * i] = map_to_0;
            } else {
                acc[2 * i] = map_to_1;
            }

            let beta = (alpha + ((p + 1) / 2)) % p;
            if self.output_encodings_0.contains(&(beta as u32)) {
                acc[2 * i + 1] = ((p as u32) - map_to_0) % p as u32;
            } else {
                acc[2 * i + 1] = ((p as u32) - map_to_1) % p as u32;
            }
        }

        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_accumulator() {
        let encoding = Encoding {
            tt_value: 4294836226,
            pin_count: 6,
            p: 23,
            input_mappings_1: vec![1, 2, 3, 3, 3, 11],
            output_encodings_0: vec![0, 1, 2, 3, 4, 6, 7, 9, 10, 12, 14, 15, 17, 18, 20, 21],
            output_encodings_1: vec![5, 8, 11, 13, 16, 19, 22],
        };
        let acc = encoding.create_accumulator();
        println!("Acc: {:?}", acc);
    }
}
