use halo2_proofs::{
    circuit::{Layouter, Table},
    //pasta::pallas,
    plonk::{Advice, Column, Constraint, Constraints, ConstraintSystem, Error, Expression, Selector, Instance},
    poly::Rotation, arithmetic::FieldExt,
};

use group::ff::{Field, PrimeField};
use std::marker::PhantomData;

use crate::compression::*;

use pasta_curves::pallas::Base;

//use compression_gate::CompressionGate;

#[derive(Clone)]
struct Blake2bParams<F: FieldExt> {
    // Blake2b constants
    iv: [Expression<F>; 8],
    sigma: [[Expression<F>; 16]; 12],

    // Lookup table columns
    r1: Column<Table>,
    r2: Column<Table>,
    r3: Column<Table>,
    r4: Column<Table>,
}

struct CompressionConfig {
    lookup: PhantomData<()>,
    // Define advice columns
    advice: [Column<Advice>; 16],
    // Define selectors
    s1: Selector,
    s2: Selector,
    s3: Selector,
    s4: Selector,
}

impl CompressionConfig {
    pub(super) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        message: [Column<Advice>; 16],
    ) -> Self {
        // Define advice columns
        let advice = (0..16)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Define selectors
        let s1 = meta.selector();
        let s2 = meta.selector();
        let s3 = meta.selector();
        let s4 = meta.selector();

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
    meta: &mut ConstraintSystem<pallas::Base>,
    params: &Blake2bParams<F>,
    v: &mut [Expression<F>; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: Expression<F>,
    y: Expression<F>,
) -> Vec<Expression<F>> {
    // Look up table columns
    let r1 = meta.query_any(meta.lookup_table_column(), Rotation::cur());
    let r2 = meta.query_any(meta.lookup_table_column(), Rotation::cur());
    let r3 = meta.query_any(meta.lookup_table_column(), Rotation::cur());
    let r4 = meta.query_any(meta.lookup_table_column(), Rotation::cur());

    // Query the advice columns
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

        // Implement the Blake2b compression function using the lookup tables and advice columns
        // Query selectors for constants
        let r1 = meta.query_selector("r1");
        let r2 = meta.query_selector("r2");
        let r3 = meta.query_selector("r3");
        let r4 = meta.query_selector("r4");

let updated_v = CompressionGate::g_func(&mut v, a, b, c, d, x, y, r1, r2, r3, r4);

for i in 0..16 {
    meta.assign_advice(
        format!("v_{}_updated", i),
        Rotation::cur(),
        updated_v[i].clone(),
    );
}

})
}
/* 

struct Blake2bChip<F: Field> {
    config: Blake2bConfig<F>,
}

struct Blake2bConfig<F: Field> {
    q_blake2b: Selector,
    v: [Column<Advice>; 16],
    t: [Column<Advice>; 2],
    f: Column<Advice>,
    cs: Column<Advice>,
    block: Column<Advice>,
}

impl<F: Field> Chip<F> for Blake2bChip<F> {
    type Config = Blake2bConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> Blake2bChip<F> {

*/

    fn blake2b_compression(
        &self,
        layouter: &mut impl Layouter<F>,
        block: [Expression<F>; 16],
    ) -> Result<[Expression<F>; 8], Error> {
        let config = self.config();

        layouter.assign_region(
            || "blake2b compression",
            |mut region| {
                config.q_blake2b.enable(&mut region, 0)?;

                for (idx, value) in block.iter().enumerate() {
                    region.assign_advice(
                        || format!("block value {}", idx),
                        config.block,
                        0,
                        || value.evaluate(&mut region),
                    )?;
                }

                let mut v = [Expression::Constant(F::zero()); 16];

                // Initialize working variables
                for (idx, advice) in config.v.iter().enumerate() {
                    v[idx] = Expression::from(region.assign_advice(
                        || format!("v_{}", idx),
                        *advice,
                        0,
                        || Ok(F::zero()), // You should initialize these values based on the BLAKE2b initialization vectors
                    )?);
                }

                // Implement the 12 rounds of the BLAKE2b compression function
                for round in 0..12 {
                    // Apply the G function to the working variables
                    // You should implement the G function, including the mixing and permutations, based on the BLAKE2b specification
                    // ...
                }

                // Finalize the state and return the result
                let mut result = [Expression::Constant(F::zero()); 8];
                for i in 0..8 {
                    result[i] = v[i] + block[i];
                }

                Ok(result)
            },
        )
    }
}


