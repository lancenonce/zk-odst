// implementation of blake2 hashing algorithm with halo2
// this is a basic implementation with no optional features such as salting, personalized hashes, or tree hashing
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unreachable_code)]

use std::marker::PhantomData;
use bitvec::prelude::*;
use halo2_proofs::circuit::Value;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region, AssignedCell},
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Assigned},
};
//mod compression_gate;
//mod compression;
use crate::utils::{i2lebsp, lebs2ip, spread_bits};

use pasta_curves::{Fp, pallas::Base};

// pub enum Value<T> {
//     Assigned(T),
//     Unassigned,
// }

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

impl<const LEN: usize> From<&Bits<LEN>> for Assigned<Base> {
    fn from(bits: &Bits<LEN>) -> Assigned<Base> {
        assert!(LEN <= 64);
        Base::from(lebs2ip(&bits.0)).into()
    }
}

impl From<&Bits<8>> for u16 {
    fn from(bits: &Bits<8>) -> u16 {
        lebs2ip(&bits.0) as u16
    }
}

impl From<u16> for Bits<8> {
    fn from(int: u16) -> Bits<8> {
        Bits(i2lebsp::<8>(int.into()))
    }
}

impl From<&Bits<24>> for u32 {
    fn from(bits: &Bits<24>) -> u32 {
        lebs2ip(&bits.0) as u32
    }
}

impl From<u32> for Bits<24> {
    fn from(int: u32) -> Bits<24> {
        Bits(i2lebsp::<24>(int.into()))
    }
}

impl From<&Bits<23>> for u32 {
    fn from(bits: &Bits<23>) -> u32 {
        lebs2ip(&bits.0) as u32
    }
}

impl From<u32> for Bits<23> {
    fn from(int: u32) -> Bits<23> {
        Bits(i2lebsp::<23>(int.into()))
    }
}


impl From<&Bits<1>> for u16 {
    fn from(bits: &Bits<1>) -> u16 {
        lebs2ip(&bits.0) as u16
    }
}

impl From<u16> for Bits<1> {
    fn from(int: u16) -> Bits<1> {
        Bits(i2lebsp::<1>(int.into()))
    }
}

impl From<u16> for Bits<7> {
    fn from(int: u16) -> Bits<7> {
        Bits(i2lebsp::<7>(int.into()))
    }
}

#[derive(Clone, Debug)]
pub struct AssignedBits<const LEN: usize>(AssignedCell<Bits<LEN>, Base>);


impl<const LEN: usize> std::ops::Deref for AssignedBits<LEN> {
    type Target = AssignedCell<Bits<LEN>, Base>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LEN: usize> AssignedBits<LEN> {
    fn assign_bits<A, AR, T: TryInto<[bool; LEN]> + std::fmt::Debug + Clone>(
        region: &mut Region<'_, Base>,
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
            Any::Advice(_) => {
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
        region: &mut Region<'_, Base>,
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
            Any::Advice(_) => {
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
        region: &mut Region<'_, Base>,
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
            Any::Advice(_) => {
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
        region: &mut Region<'_, Base>,
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
            Any::Advice(_) => {
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
        region: &mut Region<'_, Base>,
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
            Any::Advice(_) => {
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
        region: &mut Region<'_, Base>,
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
            Any::Advice(_) => {
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
pub struct BitChunk(AssignedBits<8>, AssignedBits<24>, AssignedBits<23>, AssignedBits<1>, AssignedBits<7>);

impl From<(AssignedBits<8>, AssignedBits<24>, AssignedBits<23>, AssignedBits<1>, AssignedBits<7>)> for BitChunk {
    fn from(portions: (AssignedBits<8>, AssignedBits<24>, AssignedBits<23>, AssignedBits<1>, AssignedBits<7>)) -> Self {
        Self(portions.0, portions.1, portions.2, portions.3, portions.4)
    }
}

pub trait BitChunkSpread {
    fn chunk_mask(&self, chunk_size: usize) -> u64 ;
    fn split_into(&self, chunk_size: usize) -> Vec<Self>
    where
        Self: Sized;
    fn combine(chunks: &[Self]) -> Self
    where
        Self: Sized;
}

// written by chatgpt - todo check 
impl BitChunkSpread for BitChunk {
    fn chunk_mask(&self, chunk_size: usize) -> u64 {
        assert!(chunk_size > 0 && chunk_size <= 64);
        (1u64 << chunk_size) - 1
    }

    fn split_into(&self, chunk_size: usize) -> Vec<Self> {
        assert!(chunk_size > 0 && chunk_size <= 64);
        let mask = Self::chunk_mask(chunk_size);
        let mut chunks = Vec::new();
        let mut remaining = self.value;
        let mut shift = 0;

        while remaining > 0 {
            let value = remaining & mask;
            chunks.push(Self::new(value, chunk_size));
            remaining >>= chunk_size;
            shift += chunk_size;
        }

        if shift < self.length {
            let value = self.value >> shift;
            let len = self.length - shift;
            chunks.push(Self::new(value, len));
        }

        chunks
    }

    fn combine(chunks: &[Self]) -> Self {
        let mut value = 0u64;
        let mut shift = 0;

        for chunk in chunks {
            let chunk_value = chunk.get() & Self::chunk_mask(chunk.len());
            value |= chunk_value << shift;
            shift += chunk.len();
        }

        Self::new(value, shift)
    }
}





