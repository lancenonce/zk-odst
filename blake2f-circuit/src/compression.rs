use halo2_proofs::{
    circuit::{Layouter},
    //pasta::pallas,
    plonk::{Advice, Column, Constraint, Constraints, ConstraintSystem, Error, Expression, Selector, Instance},
    poly::Rotation, arithmetic::FieldExt,
};

use group::ff::{Field, PrimeField};
use std::marker::PhantomData;

mod compression_gate;
mod bit_chunk;

use pasta_curves::pallas::Base;

const ROUNDS: usize = 12;
const STATE: usize = 8;

use compression_gate::CompressionGate;
use bit_chunk::BitChunkSpread;

// BLAKE2 Sigma constant
pub const BLAKE2B_SIGMA: [[u8; 16]; 10] = [
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

pub const BLAKE2B_IV: [u64; STATE] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

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

pub struct CompressionConfig {
    lookup: PhantomData<()>,
    //TODO: define advice and selectors
    // todo what the selectors be used for
    advice: [Column<Advice>; 16],
    s1: Selector,
    s2: Selector,
    s3: Selector,
    s4: Selector,
}

impl CompressionConfig { pub(super) fn configure(
    meta: &mut ConstraintSystem<Base>,
    message: [Column<Advice>; 16],
) -> Self {
    // Define advice columns
    let advice = (0..16)
        .map(|_| meta.advice_column())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // Define selectors
    let r1 = meta.selector();
    let r2 = meta.selector();
    let r3 = meta.selector();
    let r4 = meta.selector();

    // Return the CompressionConfig struct
    Self {
        lookup: PhantomData,
        advice,
        s1,
        s2,
        s3,
        s4,
    }
}


    fn blake2_g<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<Base>,
        v: &mut [Expression<F>; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        x: Expression<F>,
        y: Expression<F>,
    ) -> Vec<Expression<F>> {

        // todo are the lookups required for const r1,r2,r3 and r4? i dont think so check?
        //selector column
        let r1 = meta.lookup_table_column(r1);
        meta.lookup(|meta| {
            let r_1 = meta.query_any(a, Rotation::cur());
            vec![(r_1, r1)]
        });
        let r2 = meta.lookup_table_column(r2);
        meta.lookup(|meta| {
            let r_2 = meta.query_any(a, Rotation::cur());
            vec![(r_2, r2)]
        });
        let r3 = meta.lookup_table_column(r3);
        meta.lookup(|meta| {
            let r_3 = meta.query_any(a, Rotation::cur());
            vec![(r_3, r3)]
        });
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

            // why query selectors for constants
            // use query table column instead
            let r1 = meta.query_selector("r1");
            let r2 = meta.query_selector("r2");
            let r3 = meta.query_selector("r3");
            let r4 = meta.query_selector("r4");

        
            let updated_v = CompressionGate::g_func(&mut v, a, b, c, d, x, y);
        
            for i in 0..16 {
                meta.assign_advice(
                    format!("v_{}_updated", i),
                    Rotation::cur(),
                    updated_v[i].into(),
                );
            }
        });
    }

    // todo written by chatgpt - check if this makes sense
    fn compression_function(&self, 
        layouter: &mut impl Layouter<Base>
    ) -> Result<(), Error> {

        layouter.assign_region(|| "blake2b compression",
         |mut region| {
            let mut v = [Base::zero(); 16];
            for (idx, iv) in BLAKE2B_IV.iter().enumerate() {
                v[idx] = Base::from_u64(*iv);
            }
    
            // Assign the initial values of v to the advice cells
            for (idx, value) in v.iter().enumerate() {
                region.assign_advice(|| format!("v_{}", idx), self.advice[idx], 0, || Ok(*value))?;
            }
    
            // Iterate through the rounds
            for round in 0..12 {
                let sigma = &BLAKE2B_SIGMA[round];
                self.selector.enable(&mut region, round)?;
    
                for idx in 0..8 {
                    let a = 2 * idx;
                    let b = 2 * idx + 1;
                    let c = (2 * idx + 2) % 16;
                    let d = (2 * idx + 3) % 16;
    
                    let x = Base::from_u64(sigma[a] as u64);
                    let y = Base::from_u64(sigma[b] as u64);
    
                    let expressions: [Expression<Base>; 16] = (0..16)
                        .map(|i| Expression::from(region.get_advice(self.advice[i], round)))
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap();
    
                    self.blake2_g(&mut region, &mut expressions.clone(), a, b, c, d, Expression::Constant(x), Expression::Constant(y))?;
    
                    for (idx, expression) in expressions.iter().enumerate() {
                        region.assign_advice(|| format!("v_{}", idx), self.advice[idx], round + 1, || {
                            Ok(expression.evaluate(&|_| { Base::zero() }))
                        })?;
                    }
                }
            }
            Ok(())
        })
    }
    

}



