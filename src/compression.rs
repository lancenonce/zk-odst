use halo2_proofs::{
    circuit::{Layouter, Value},
    pasta::pallas,
    plonk::{Advice, Column, Constraint, Constraints, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

use std::convert::TryInto;
use std::ops::Range;

mod compression_gates;
mod compression_util;
mod subregion_digest;
mod subregion_initial;
mod subregion_main;

use group::ff::{Field, PrimeField};
use compression_gates::CompressionGate;

use std::marker::PhantomData;

// This is where we will define the message and state chunks that serve as inputs to the compression function
#[derive(Clone, Debug)]
pub struct MessageChunk(u64);

#[derive(Clone, Debug)]
// This type should be a u64 field element
pub struct StateChunk(u64);

const DIGEST_SIZE: usize = 8;

pub trait UpperSigmaVar<
    const A_LEN: usize,
    const B_LEN: usize,
    const C_LEN: usize,
    const D_LEN: usize,
>
{
    fn spread_a(&self) -> Value<[bool; A_LEN]>;
    fn spread_b(&self) -> Value<[bool; B_LEN]>;
    fn spread_c(&self) -> Value<[bool; C_LEN]>;
    fn spread_d(&self) -> Value<[bool; D_LEN]>;

    fn xor_upper_sigma(&self) -> Value<[bool; 64]> {
    }
}

#[derive(Clone, Debug)]
pub struct AbcdVar {
    a: SpreadVar<2, 4>,
    b: SpreadVar<11, 22>,
    c_lo: SpreadVar<3, 6>,
    c_mid: SpreadVar<3, 6>,
    c_hi: SpreadVar<3, 6>,
    d: SpreadVar<10, 20>,
}

impl AbcdVar {
    fn a_range() -> Range<usize> {
    }

    fn b_range() -> Range<usize> {
    }

    fn c_lo_range() -> Range<usize> {
    }

        16..19
    }

    fn c_hi_range() -> Range<usize> {
    }

    fn d_range() -> Range<usize> {
    }

    fn pieces(val: u32) -> Vec<Vec<bool>> {
    }
}

impl UpperSigmaVar<4, 22, 18, 20> for AbcdVar {
    fn spread_a(&self) -> Value<[bool; 4]> {
    }

    fn spread_b(&self) -> Value<[bool; 22]> {
    }

    fn spread_c(&self) -> Value<[bool; 18]> {
    }

    fn spread_d(&self) -> Value<[bool; 20]> {
    }
}

#[derive(Clone, Debug)]
pub struct EfghVar {
    a_lo: SpreadVar<3, 6>,
    a_hi: SpreadVar<3, 6>,
    b_lo: SpreadVar<2, 4>,
    b_hi: SpreadVar<3, 6>,
    c: SpreadVar<14, 28>,
    d: SpreadVar<7, 14>,
}

impl EfghVar {
    fn a_lo_range() -> Range<usize> {
    }

    fn a_hi_range() -> Range<usize> {
    }

    fn b_lo_range() -> Range<usize> {
    }

    fn b_hi_range() -> Range<usize> {
    }

    fn c_range() -> Range<usize> {
    }

    fn d_range() -> Range<usize> {
    }

    fn pieces(val: u32) -> Vec<Vec<bool>> {
    }
}

impl UpperSigmaVar<12, 10, 28, 14> for EfghVar {
    fn spread_a(&self) -> Value<[bool; 12]> {
    }

    fn spread_b(&self) -> Value<[bool; 10]> {
    }

    fn spread_c(&self) -> Value<[bool; 28]> {
    }

    fn spread_d(&self) -> Value<[bool; 14]> {
    }
}

/// The internal state for BLAKE2 and sha-256. Represents the h[0..7] internal state of the hash
#[derive(Clone, Debug)]
pub struct State {
    a: Option<StateChunk>,
    b: Option<StateChunk>,
    c: Option<StateChunk>,
    d: Option<StateChunk>,
    e: Option<StateChunk>,
    f: Option<StateChunk>,
    g: Option<StateChunk>,
    h: Option<StateChunk>,
}

impl State {
    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        a: StateChunk,
        b: StateChunk,
        c: StateChunk,
        d: StateChunk,
        e: StateChunk,
        f: StateChunk,
        g: StateChunk,
        h: StateChunk,
    ) -> Self {
        State {
            a: Some(a),
            b: Some(b),
            c: Some(c),
            d: Some(d),
            e: Some(e),
            f: Some(f),
            g: Some(g),
            h: Some(h),
        }
    }

    pub fn empty_state() -> Self {
        State {
            a: None,
            b: None,
            c: None,
            d: None,
            e: None,
            f: None,
            g: None,
            h: None,
        }
    }
}

//TODO add in right word
#[derive(Clone, Debug)]
pub enum StateWord {
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
}

#[derive(Clone, Debug)]
pub(super) struct CompressionConfig {
    lookup: SpreadInputs,
    message_schedule: Column<Advice>,
    extras: [Column<Advice>; 6],

    s_ch: Selector,
    s_ch_neg: Selector,
    s_maj: Selector,
    s_h_prime: Selector,
    s_a_new: Selector,
    s_e_new: Selector,

    s_upper_sigma_0: Selector,
    s_upper_sigma_1: Selector,

    // Decomposition gate for AbcdVar
    s_decompose_abcd: Selector,
    // Decomposition gate for EfghVar
    s_decompose_efgh: Selector,

    s_digest: Selector,
}

impl Table16Assignment for CompressionConfig {}

impl CompressionConfig {
    pub(super) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        lookup: SpreadInputs,
        message_schedule: Column<Advice>,
        extras: [Column<Advice>; 6],
    ) -> Self {}

    /// Initialize compression with a constant Initialization Vector of 32-byte words.
    /// Returns an initialized state.
    pub(super) fn initialize_with_iv(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        init_state: [u32; STATE],
    ) -> Result<State, Error> {}

    /// Initialize compression with some initialized state. This could be a state
    /// output from a previous compression round.
    pub(super) fn initialize_with_state(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        init_state: State,
    ) -> Result<State, Error> {}

    /// Given an initialized state and a message schedule, perform 64 compression rounds.
    pub(super) fn compress(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        initialized_state: State,
        w_halves: [(AssignedBits<16>, AssignedBits<16>); ROUNDS],
    ) -> Result<State, Error> {}

    /// After the final round, convert the state into the final digest.
    pub(super) fn digest(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        state: State,
    ) -> Result<[BlockWord; DIGEST_SIZE], Error> {}
}

pub struct CompressionGate<F: Field>(PhantomData<F>);

impl<F: PrimeField> CompressionGate<F> {
    fn ones() -> Expression<F> {
        Expression::Constant(F::ONE)
    }

    // Implement G function
    pub fn g_func(Vec<StateChunk>>, a: Value<F>, b: Value<F>, c: Value<F>, d: Value<F>, x: MessageChunk, y: MessageChunk) -> Vec<StateChunk>> {

    }
    // Implement G function
    pub fn f_func(Vec<StateChunk>>, a: Value<F>, b: Value<F>, c: Value<F>, d: Value<F>, x: MessageChunk, y: MessageChunk) -> Vec<StateChunk>> {

    }
}
