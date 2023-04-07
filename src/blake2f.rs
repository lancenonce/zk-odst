// implementation of blake2 hashing algorithm with halo2
// this is a basic implementation with no optional features such as salting, personalized hashes, or tree hashing
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unreachable_code)]

use std::marker::PhantomData;
use bitvec::prelude::*;

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

/// The sequence of bits representing a u64 in little-endian order.
///
/// # Panics
///
/// Panics if the expected length of the sequence `NUM_BITS` exceeds
/// 64.
pub fn i2lebsp<const NUM_BITS: usize>(int: u64) -> [bool; NUM_BITS] {
    /// Takes in an FnMut closure and returns a constant-length array with elements of
    /// type `Output`.
    fn gen_const_array<Output: Copy + Default, const LEN: usize>(
        closure: impl FnMut(usize) -> Output,
    ) -> [Output; LEN] {
        gen_const_array_with_default(Default::default(), closure)
    }

    fn gen_const_array_with_default<Output: Copy, const LEN: usize>(
        default_value: Output,
        closure: impl FnMut(usize) -> Output,
    ) -> [Output; LEN] {
        let mut ret: [Output; LEN] = [default_value; LEN];
        for (bit, val) in ret.iter_mut().zip((0..LEN).map(closure)) {
            *bit = val;
        }
        ret
    }

    assert!(NUM_BITS <= 64);
    gen_const_array(|mask: usize| (int & (1 << mask)) != 0)
}

/// Returns the integer representation of a little-endian bit-array.
/// Panics if the number of bits exceeds 64.
pub fn lebs2ip<const K: usize>(bits: &[bool; K]) -> u64 {
    assert!(K <= 64);
    bits.iter()
        .enumerate()
        .fold(0u64, |acc, (i, b)| acc + if *b { 1 << i } else { 0 })
}


/// Helper function that interleaves a little-endian bit-array with zeros
/// in the odd indices. That is, it takes the array
///         [b_0, b_1, ..., b_n]
/// to
///         [b_0, 0, b_1, 0, ..., b_n, 0].
/// Panics if bit-array is longer than 16 bits.
pub fn spread_bits<const DENSE: usize, const SPREAD: usize>(
    bits: impl Into<[bool; DENSE]>,
) -> [bool; SPREAD] {
    assert_eq!(DENSE * 2, SPREAD);
    assert!(DENSE <= 16);

    let bits: [bool; DENSE] = bits.into();
    let mut spread = [false; SPREAD];

    for (idx, bit) in bits.iter().enumerate() {
        spread[idx * 2] = *bit;
    }

    spread
}


#[derive(Clone, Debug)]
/// Little-endian bits (up to 64 bits)
pub struct Bits<const LEN: usize>([bool; LEN]);

impl<const LEN: usize> Bits<LEN> {
    fn spread<const SPREAD: usize>(&self) -> [bool; SPREAD] {
        spread_bits(self.0)
    }
}

impl<const LEN: usize> std::ops::Deref for Bits<LEN> {
    type Target = [bool; LEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LEN: usize> From<[bool; LEN]> for Bits<LEN> {
    fn from(bits: [bool; LEN]) -> Self {
        Self(bits)
    }
}

impl<const LEN: usize> From<&Bits<LEN>> for [bool; LEN] {
    fn from(bits: &Bits<LEN>) -> Self {
        bits.0
    }
}

impl<const LEN: usize> From<&Bits<LEN>> for Assigned<pallas::Base> {
    fn from(bits: &Bits<LEN>) -> Assigned<pallas::Base> {
        assert!(LEN <= 64);
        pallas::Base::from(lebs2ip(&bits.0)).into()
    }
}

impl From<&Bits<8>> for u16 {
    fn from(bits: &Bits<8>) -> u16 {
        lebs2ip(&bits.0) as u16
    }
}

impl From<u16> for Bits<8> {
    fn from(int: u16) -> Bits<8> {
        Bits(i2lebsp::<16>(int.into()))
    }
}

impl From<&Bits<24>> for u32 {
    fn from(bits: &Bits<24>) -> u32 {
        lebs2ip(&bits.0) as u32
    }
}

impl From<u32> for Bits<24> {
    fn from(int: u32) -> Bits<24> {
        Bits(i2lebsp::<32>(int.into()))
    }
}

impl From<&Bits<23>> for u32 {
    fn from(bits: &Bits<23>) -> u32 {
        lebs2ip(&bits.0) as u32
    }
}

impl From<u32> for Bits<23> {
    fn from(int: u32) -> Bits<23> {
        Bits(i2lebsp::<32>(int.into()))
    }
}


impl From<&Bits<1>> for u16 {
    fn from(bits: &Bits<1>) -> u16 {
        lebs2ip(&bits.0) as u16
    }
}

impl From<u16> for Bits<1> {
    fn from(int: u16) -> Bits<1> {
        Bits(i2lebsp::<16>(int.into()))
    }
}

impl From<&Bits<1>> for u16 {
    fn from(bits: &Bits<1>) -> u16 {
        lebs2ip(&bits.0) as u16
    }
}

impl From<u16> for Bits<7> {
    fn from(int: u16) -> Bits<7> {
        Bits(i2lebsp::<16>(int.into()))
    }
}

#[derive(Clone, Debug)]
pub struct AssignedBits<const LEN: usize>(AssignedCell<Bits<LEN>, pallas::Base>);

#[derive(Clone, Debug)]
pub struct AssignedBits<const LEN: usize>(AssignedCell<Bits<LEN>, pallas::Base>);

impl<const LEN: usize> std::ops::Deref for AssignedBits<LEN> {
    type Target = AssignedCell<Bits<LEN>, pallas::Base>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LEN: usize> AssignedBits<LEN> {
    fn assign_bits<A, AR, T: TryInto<[bool; LEN]> + std::fmt::Debug + Clone>(
        region: &mut Region<'_, pallas::Base>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<T>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
        <T as TryInto<[bool; LEN]>>::Error: std::fmt::Debug,
    {
        let value: Value<[bool; LEN]> = value.map(|v| v.try_into().unwrap());
        let value: Value<Bits<LEN>> = value.map(|v| v.into());

        let column: Column<Any> = column.into();
        match column.column_type() {
            Any::Advice => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

impl AssignedBits<8> {
    fn value_u16(&self) -> Value<u16> {
        self.value().map(|v| v.into())
    }

    fn assign<A, AR>(
        region: &mut Region<'_, pallas::Base>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<u16>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let column: Column<Any> = column.into();
        let value: Value<Bits<8>> = value.map(|v| v.into());
        match column.column_type() {
            Any::Advice => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

impl AssignedBits<24> {
    fn value_u32(&self) -> Value<u32> {
        self.value().map(|v| v.into())
    }

    fn assign<A, AR>(
        region: &mut Region<'_, pallas::Base>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<u32>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let column: Column<Any> = column.into();
        let value: Value<Bits<24>> = value.map(|v| v.into());
        match column.column_type() {
            Any::Advice => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}
impl AssignedBits<23> {
    fn value_u32(&self) -> Value<u32> {
        self.value().map(|v| v.into())
    }

    fn assign<A, AR>(
        region: &mut Region<'_, pallas::Base>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<u32>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let column: Column<Any> = column.into();
        let value: Value<Bits<23>> = value.map(|v| v.into());
        match column.column_type() {
            Any::Advice => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

impl AssignedBits<1> {
    fn value_u16(&self) -> Value<u16> {
        self.value().map(|v| v.into())
    }

    fn assign<A, AR>(
        region: &mut Region<'_, pallas::Base>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<u16>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let column: Column<Any> = column.into();
        let value: Value<Bits<1>> = value.map(|v| v.into());
        match column.column_type() {
            Any::Advice => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

impl AssignedBits<7> {
    fn value_u16(&self) -> Value<u16> {
        self.value().map(|v| v.into())
    }

    fn assign<A, AR>(
        region: &mut Region<'_, pallas::Base>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<u16>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let column: Column<Any> = column.into();
        let value: Value<Bits<7>> = value.map(|v| v.into());
        match column.column_type() {
            Any::Advice => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

#[derive(Clone, Debug)]
pub struct BitChunk(AssignedBits<8>, AssignedBits<24>, AssignedBits<23>, AssignedBits<1>, AssignedBits<8>);

impl From<(AssignedBits<8>, AssignedBits<24>, AssignedBits<23>, AssignedBits<1>, AssignedBits<8>)> for bitChunk {
    fn from(portions: (AssignedBits<8>, AssignedBits<24>, AssignedBits<23>, AssignedBits<1>, AssignedBits<8>)) -> Self {
        Self(portions.0, halves.1, portions.2, portions.3, portions.4)
    }
}

impl BitChunkSpread {
    pub fn value(&self) -> Value<u64> {
        self.0=self.get(0..7)
        self.1=self.get(8..23)
        self.2=self.get(24..57)
        self.3=self.get(57)
        self.4=self.get(58..64)

    }
}


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
