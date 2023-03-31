use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::*,
    plonk::*,
    poly::Rotation,
    pasta::Fp,
};

#[derive(Clone, Debug)]
struct ACell<F: FieldExt>(AssignedCell<F,F>);

#[derive(Clone, Debug)]
struct FiboConfig{
    pub advice: [Column<Advice>; 3],
    pub selector: Selector,
}

struct FiboChip<F: FieldExt> {
    config: FiboConfig,
    _marker: std::marker::PhantomData<F>,
}

impl<F: FieldExt> FiboChip<F> {
    fn construct(config: FiboConfig) -> Self {
        Self {
            config, 
            _marker: PhantomData
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>, advice: [Column<Advice>; 3]) -> FiboConfig {
        let (col_a, col_b, col_c) = (advice[0], advice[1], advice[2]);
        let selector = meta.selector();

        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);

        /*
        a   b   c   s
        *   *   *   *
        *   *   *   *

        where we constrain s * (a + b - c) = 0
        
         */

        meta.create_gate("add", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            // a + b = c
            vec![s * (a + b - c)]
        });

        FiboConfig {
            advice: [a, b, c],
            selector,
        }
    }

    fn assign_first_row(&self, mut layouter: impl Layouter<F>, a: Option<F>, b: Option<F>) -> Result<(ACell, ACell, ACell), Error>{
        layouter.assign_region(
            || "first row",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                // let a_cell = region.assign_advice_from_instance(||"1", self.config.instance, 0, self.config.advice[0], 0)?;

                let a_cell = region.assign_advice(
                    || "a",
                    self.config.advice[0],
                    0,
                    || a.or_then(Error::Synthesis),
                ).map(ACell)?;
                let b_cell = region.assign_advice(
                    || "b",
                    self.config.advice[1],
                    0,
                    || b.or_then(Error::Synthesis),
                ).map(ACell)?;

                let c_val = a.and_then(|a| b.map(|b| a + b));

                let c_cell = region.assign_advice(
                    || "b",
                    self.config.advice[2],
                    0,
                    || c_val.or_then(Error::Synthesis),
                ).map(ACell)?;

                Ok((a_cell, b_cell, c_cell))
            }
        )
    }

    fn assign_row(&self, &mut layout: impl Layouter<F>, prev_b: ACell<F>, prev_c: ACell<F>) -> Result<ACell<F>, Error> {
        layouter.assign_region(
            || "next row",
            |region| {
                self.config.selector.enable(&mut region, 0);

                prev_b.0.copy_advice(|| "a", &mut region, self.config.advice[0], 0)?;
                prev_c.0.copy_advice(|| "b", &mut region, self.config.advice[1], 0)?;

                let c_val = prev_b.0.value().and_then(
                    |b| {
                        prev_c.0.value().map(|c| *b + *c)
                    }
                );

                region.assign_advice( 
                    || "c",
                    self.config.advice[2], 
                    0,
                    || c.ok_or(Error::Synthesis),
                ).map(ACell)?;

                Ok(c_cell)
            }
        )
    }

    pub fn expose_public(&self, &mut layouter: impl Layouter<F>, &cell: &ACell<F>, row: usize) {
        layouter.constrain_instance(cell.0.cell(), self.config.instance, row)
    }
}

#[derive(Default)]
struct TheCircuit<F> {
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<F: FieldExt> Circuit<F> for TheCircuit<F> {
    type Config = FiboConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            a: None,
            b: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let instance = meta.instance_column();
        FiboChip::configure(meta, [col_a, col_b, col_c], )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = FiboChip::construct(config);

        let (_, mut prev_b, mut prev_c) = chip.assign_first_row(
            // name of the region
            layouter.namespace(|| "first row"),
            self.a, self.b
        );

        chip.expose_public(layouter.namespace(|| "private a"), &prev_a, 0);
        chip.expose_public(layouter.namespace(|| "private b"), &prev_b, 1);


        // We start at 3 because our first three values are specified in the first row
        for _i in 3..10 {
            let (a, b, c) = chip.assign_row(
                layouter.namespace(|| "next row"),
                &prev_b,
                &prev_c,
            );
            prev_b = b;
            prev_c = c;
        }

        chip.expose_public(layouter.namespace(|| "out"), &prev_c, 2)?;

        Ok(())
    }
}
fn main() {
    let k = 4;

    let a = Fp::from(1);
    let b = Fp::from(1);
    let out = Fp::from(55);

    let circuit = TheCircuit {
        a: Some(a),
        b: Some(b),
    };

    let public_input = vec![a, b, out];

    // Generate a mock prover and pass in k, a circuit instance, and a vector of instance (public) values (empty)
    let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
    prover.assert_satisfied();
}
