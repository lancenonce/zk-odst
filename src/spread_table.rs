// imports
use halo2_proofs::{
    plonk::{TableColumn}
}
use group::ff::{Field};
// definition of Struct SpreadWord with just one field called spread
#[derive(Clone, Copy, Debug)]
pub(super) struct SpreadWord<const SPREAD: usize> {
    spread: [bool; SPREAD],
}

impl<const SPREAD: usize> SpreadWord<SPREAD> {
    pub(super) fn new(spread: [bool; SPREAD]) -> Self {
        Self { spread: spread }
    }


}

// definition of struct SpreadInputs that take in the input advice columns 
#[derive(Clone, Copy, Debug)]
pub(super) struct SpreadInputs {
    pub(super) spread: Column<Advice>
}

// definition of Struct SpreadTable with just one field called table
#[derive(Clone, Copy, Debug)]
pub(super) struct SpreadTable{
    pub(super) spread: TableColumn
}

// definition of Struct SpreadTable Config with a SpreadWord and a Spreadtable
#[derive(Clone, Copy, Debug)]
pub(super) struct SpreadTableConfig {
    pub(super) input: SpreadInput,
    pub(super) table: SpreadTable,
}

// definition of SpreadTableChip that defines a chip we can export for the various spreads we use
#[derive(Clone, Debug)]
pub(super) SpreadTableChip<F: Field> {
    config: SpreadTableConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> for SpreadTableChip<F> {
    type Config = SpreadTableConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: PrimeField> SpreadTableChip<F> {
    pub fn configure() -> <Self as Chip<F>>::Config {
        let config = SpreadTableConfig {
            input: SpreadInput {
                spread: meta.advice_column(),
            },
            table: SpreadTable {
                spread: meta.table_column(),
            },
        };

        config
    }

    pub fn shift() -> <Self as Chip
}