use halo2_proofs::{
    circuit::{Layouter, Value},
    pasta::pallas,
    plonk::{Advice, Column, Constraint, Constraints, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

use group::ff::{Field, PrimeField};
use std::marker::PhantomData;

// This is where we will define the message and state chunks that serve as inputs to the compression function
#[derive(Clone, Debug)]
pub struct MessageChunk(u64);

#[derive(Clone, Debug)]
// This type should be a u64 field element
pub struct StateChunk(u64);

/// The internal state for BLAKE2. Represents the h[0..7] internal state of the hash
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

pub struct CompressionGate<F: Field>(PhantomData<F>);

impl<F: PrimeField> CompressionGate<F> {
    fn ones() -> Expression<F> {
        Expression::Constant(F::ONE)
    }

    // Implement G function
    pub fn g_func(Vec<StateChunk>>, a: Value<F>, b: Value<F>, c: Value<F>, d: Value<F>, x: MessageChunk, y: MessageChunk) -> Vec<StateChunk>> {

    }
}

