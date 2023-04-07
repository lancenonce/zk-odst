use halo2_proofs::{
    circuit::{Layouter, Value},
    pasta::pallas,
    plonk::{Advice, Column, Constraint, Constraints, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

use group::ff::{Field, PrimeField};
use std::marker::PhantomData;
mod compression_gate;
use compression_gate::CompressionGate;

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

struct CompressionConfig {
    lookup: ,
    //TODO: define advice and selectors
}

impl CompressionConfig {
    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        // define advice and selectors
        Self {
            // define advice and selectors
        }
    }

    fn blake2_g(
        v: &mut [Expression<F>; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        x: Expression<F>,
        y: Expression<F>,
    ) -> Vec<Expression<F>> {
        let r1 = lookup.r1;
        let r2 = lookup.r2;
        let r3 = lookup.r3;
        let r4 = meta.lookup_table_column(r4);
        meta.lookup(|meta| {
            let r_4 = meta.query_any(a, Rotation::cur());
            vec![(r_4, r4)]
        });

        meta.create_gate("blake2_g", |meta| {
            
            let v = (0..16)
                .map(|i| meta.query_advice(format!("v_{}", i), Rotation::cur()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let a = meta.query_advice("a", Rotation::cur());
            let b = meta.query_advice("b", Rotation::cur());
            let c = meta.query_advice("c", Rotation::cur());
            let d = meta.query_advice("d", Rotation::cur());
            let x = meta.query_advice("x", Rotation::cur());
            let y = meta.query_advice("y", Rotation::cur());
            // query selectors for constants
            // use query table column instead
            let x = meta.lookup_table_column();
            let r1 = meta.query_selector("r1");
            let r2 = meta.query_selector("r2");
            let r3 = meta.query_selector("r3");
            let r4 = meta.query_selector("r4");

        
            CompressionGate::g_func(&mut v, a, b, c, d, x, y, r1, r2, r3, r4));
        
            for i in 0..16 {
                meta.assign_advice(
                    format!("v_{}_updated", i),
                    Rotation::cur(),
                    updated_v[i].into(),
                );
            }
        });
    }

    // compression function should be implemented here

}



