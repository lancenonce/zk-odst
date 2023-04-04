// implementation of blake2 hashing algorithm with halo2
// this is a basic implementation with no optional features such as salting, personalized hashes, or tree hashing
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unreachable_code)]

use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{Advice, Any, Column, ConstraintSystem, Error},
};
mod compression_gate;
mod compression;

// we use 12 rounds for BLAKE2
const ROUNDS: usize = 12;
const STATE: usize = 8;

// BLAKE2 Sigma constant
pub const BLAKE2B_SIGMA: [[u8; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

pub const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

#[derive(Clone, Debug)]
pub struct Blake2fTable {
    id: Column<Advice>,
}

impl Blake2fTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            id: meta.advice_column(),
        }
    }

    pub fn columns(&self) -> Vec<Column<Any>> {
        vec![self.id.into()]
    }

    pub fn annotations(&self) -> Vec<String> {
        vec![String::from("id")]
    }
}

#[derive(Clone, Debug)]
pub struct Blake2fConfig<F> {
    table: Blake2fTable,
    _marker: PhantomData<F>,
    compression: CompressionConfig,
}

impl<F: FieldExt> Blake2fConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, table: Blake2fTable) -> Self {
        Self {
            table,
            _marker: PhantomData,
        };

        

    }

}

#[derive(Clone, Debug, Default)]
pub struct Blake2fWitness {
    pub rounds: u32,
    pub h: [u64; 8],
    pub m: [u64; 16],
    pub t: [u64; 2],
    pub f: bool,
}

#[derive(Clone, Debug)]
pub struct Blake2fChip<F> {
    config: Blake2fConfig<F>,
    data: Vec<Blake2fWitness>,
}

impl<F: FieldExt> Blake2fChip<F> {
    pub fn construct(config: Blake2fConfig<F>, data: Vec<Blake2fWitness>) -> Self {
        Self { config, data }
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}

// here we add the implementation of the BLAKE2 instructions for the BLAKE2 Chip
impl Blake2fInstructions<F> for Blake2fChip {
    type State = State;
    type BlockWord = BlockWord;
    
    // Used during the first round when we initialize the block with IV
    fn initialization_vector(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
    ) -> Result<State, Error> {
        // replace Ok(State) with call from compression.rs
        Ok(State)
    }

    // Since the compression algorithm has multiple rounds, we can initialize a table with a previous state
    fn initialization(
        &self,
        layouter: &mut impl Layouter,
        init_state: &Self::State,
    ) -> Result<State, Error>{
        Ok(State)
    }

    // Given an initialized state and an input message block, compress the
    // message block and return the final state.
    fn compress(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        initialized_state: &Self::State,
        input: [Self::BlockWord; super::BLOCK_SIZE],
    ) -> Result<Self::State, Error> {
        Ok(State)
    }

    fn digest(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        state: &Self::State,
    ) -> Result<[Self::BlockWord; super::DIGEST_SIZE], Error> {
        Ok(BlockWord)
    }
}

#[cfg(any(feature = "test", test))]
pub mod dev {
    use super::*;

    use ethers_core::{types::H512, utils::hex::FromHex};
    use halo2_proofs::{arithmetic::FieldExt, circuit::SimpleFloorPlanner, plonk::Circuit};
    use std::{marker::PhantomData, str::FromStr};

    lazy_static::lazy_static! {
        // https://eips.ethereum.org/EIPS/eip-152#example-usage-in-solidity
        pub static ref INPUTS_OUTPUTS: (Vec<Blake2fWitness>, Vec<H512>) = {
            let (h1, h2) = (
                <[u8; 32]>::from_hex("48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5").expect(""),
                <[u8; 32]>::from_hex("d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b").expect(""),
            );
            let (m1, m2, m3, m4) = (
                <[u8; 32]>::from_hex("6162630000000000000000000000000000000000000000000000000000000000").expect(""),
                <[u8; 32]>::from_hex("0000000000000000000000000000000000000000000000000000000000000000").expect(""),
                <[u8; 32]>::from_hex("0000000000000000000000000000000000000000000000000000000000000000").expect(""),
                <[u8; 32]>::from_hex("0000000000000000000000000000000000000000000000000000000000000000").expect(""),
            );
            (
                vec![
                    Blake2fWitness {
                        rounds: 12,
                        h: [
                            u64::from_le_bytes(h1[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(h1[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(h1[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(h1[0x18..0x20].try_into().expect("")),
                            u64::from_le_bytes(h2[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(h2[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(h2[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(h2[0x18..0x20].try_into().expect("")),
                        ],
                        m: [
                            u64::from_le_bytes(m1[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(m1[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(m1[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(m1[0x18..0x20].try_into().expect("")),
                            u64::from_le_bytes(m2[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(m2[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(m2[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(m2[0x18..0x20].try_into().expect("")),
                            u64::from_le_bytes(m3[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(m3[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(m3[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(m3[0x18..0x20].try_into().expect("")),
                            u64::from_le_bytes(m4[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(m4[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(m4[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(m4[0x18..0x20].try_into().expect("")),
                        ],
                        t: [3, 0],
                        f: true,
                    }
                ],
                vec![
                    H512::from_str("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
                    .expect("BLAKE2F compression function output is 64-bytes")
                ],
            )
        };
    }

    #[derive(Default)]
    pub struct Blake2fTestCircuit<F> {
        pub inputs: Vec<Blake2fWitness>,
        pub outputs: Vec<H512>,
        pub _marker: PhantomData<F>,
    }

    impl<F: FieldExt> Circuit<F> for Blake2fTestCircuit<F> {
        type Config = Blake2fConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
            let blake2f_table = Blake2fTable::construct(meta);
            Blake2fConfig::configure(meta, blake2f_table)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let chip = Blake2fChip::construct(config, self.inputs.clone());
            chip.load(&mut layouter)
        }
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use std::marker::PhantomData;

    use crate::dev::{Blake2fTestCircuit, INPUTS_OUTPUTS};

    #[test]
    fn test_blake2f_circuit() {
        let (inputs, outputs) = INPUTS_OUTPUTS.clone();

        let circuit: Blake2fTestCircuit<Fr> = Blake2fTestCircuit {
            inputs,
            outputs,
            _marker: PhantomData,
        };

        let k = 8;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}