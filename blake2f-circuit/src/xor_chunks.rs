

// xor mod from halo2 gadgets
pub mod xor {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression that represents the XOR of the given expression.
    pub fn expr<F: FieldExt, E: Expr<F>>(a: E, b: E) -> Expression<F> {
        a.expr() + b.expr() - 2.expr() * a.expr() * b.expr()
    }

    /// Returns a value that represents the XOR of the given value.
    pub fn value<F: FieldExt>(a: F, b: F) -> F {
        a + b - F::from(2u64) * a * b
    }
}

// compression function written by chatgpt, todo implement the spread and run test
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
    dev::{MockProver, VerifyFailure},
};
use halo2_proofs::plonk::Circuit;

use halo2_proofs::pasta::Fp;
use rand::rngs::OsRng;

// chunk size for xor and rotation are different
// for xor 
const CHUNK_SIZE: usize = 16;
const NUM_CHUNKS: usize = 64 / CHUNK_SIZE;

struct XorCircuit<F: FieldExt> {
    a: Option<[u8; NUM_CHUNKS]>,
    b: Option<[u8; NUM_CHUNKS]>,
    _marker: std::marker::PhantomData<F>,
}
#[derive(Clone)]
pub struct XorConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    out: Column<Advice>,
    table: Column<Fixed>,
}

impl<F: FieldExt> Circuit<F> for XorCircuit<F> {
    type Config = XorConfig;

    fn configure(meta: &mut ConstraintSystem<F>) -> XorConfig {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let out = meta.advice_column();
        let table = meta.fixed_column();

        meta.lookup(|meta| {
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let out = meta.query_advice(out, Rotation::cur());
            let t = meta.query_fixed(table, Rotation::cur());

            vec![(a + b - t, out)]
        });

        XorConfig { a, b, out, table }
    }

    fn synthesize(&self, config: XorConfig, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        // Fill the fixed table with XOR values for smaller chunks
        layouter.assign_table(
            || "xor_table",
            |mut table| {
                for i in 0..(1 << CHUNK_SIZE) {
                    for j in 0..(1 << CHUNK_SIZE) {
                        // todo update this xor function after using spread and interleaving of bits
                        let xor_value = i ^ j;
                        table.assign_cell(|| format!("table[{}][{}]", i, j), config.table, (i << CHUNK_SIZE) + j, || Ok(F::from_u64(xor_value as u64)))?;
                    }
                }
                Ok(())
            },
        )?;

        // Perform the XOR operation using lookup tables
        layouter.assign_region(
            || "Xor",
            |mut region| {
                for i in 0..NUM_CHUNKS {
                    let a_chunk = self.a.map(|a| a[i] as u64);
                    let b_chunk = self.b.map(|b| b[i] as u64);
                    let out_chunk = a_chunk.zip(b_chunk).map(|(a, b)| a ^ b);

                    let a_cell = region.assign_advice(|| format!("a_chunk_{}", i), config.a, i, || a_chunk.ok_or(Error::SynthesisError))?;
                    let b_cell = region.assign_advice(|| format!("b_chunk_{}", i), config.b, i, || b_chunk.ok_or(Error::SynthesisError))?;
                    let out_cell = region.assign_advice(|| format!("out_chunk_{}", i), config.out, i, || out_chunk.ok_or(Error::SynthesisError))?;

                    region.lookup_table(config.table, || {
                        a_chunk.zip(b_chunk).ok_or(Error::SynthesisError)
                    }, |table| {
                        vec![
                            (a_cell.into(), a_chunk),
                            (b_cell.into(), b_chunk),
                            (out_cell.into(), out_chunk),
                            (table, None),
                        ]
                    })?;
                }

                Ok(())
            }
        );
    }

    type FloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    
}



// Include the XorCircuit definition and other necessary imports here

fn test_xor_circuit(a: u64, b: u64) {
    let mut rng = OsRng;

    let a_chunks = u64_to_chunks(a, CHUNK_SIZE);
    let b_chunks = u64_to_chunks(b, CHUNK_SIZE);

    let circuit = XorCircuit::<Fp> {
        a: Some(a_chunks),
        b: Some(b_chunks),
        _marker: std::marker::PhantomData,
    };

    let prover = MockProver::run(1, &circuit, vec![]).unwrap();

    let result = prover.verify(&[]);
    assert!(result.is_ok());
}

fn u64_to_chunks(value: u64, chunk_size: usize) -> [u8; NUM_CHUNKS] {
    let mut chunks = [0u8; NUM_CHUNKS];
    for i in 0..NUM_CHUNKS {
        let shift = i * chunk_size;
        chunks[i] = ((value >> shift) & ((1 << chunk_size) - 1)) as u8;
    }
    chunks
}

fn main() {
    let a: u64 = 0x0123456789ABCDEF;
    let b: u64 = 0x89ABCDEF01234567;
    test_xor_circuit(a, b);
}
