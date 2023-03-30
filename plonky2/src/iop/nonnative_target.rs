use alloc::vec::Vec;
use core::ops::Range;

use crate::field::nonnative::algebra::NonnativeAlgebra;
use crate::field::extension::{Extendable, FieldExtension, OEF};
use crate::field::types::Field;
use crate::hash::hash_types::RichField;
use crate::iop::target::Target;
use crate::plonk::circuit_builder::CircuitBuilder;

/// `Target`s representing an element of an extension field.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct NonnativeTarget<const D: usize>(pub [Target; D]);

impl<const D: usize> NonnativeTarget<D> {
    pub fn to_target_array(&self) -> [Target; D] {
        self.0
    }

    pub fn frobenius<F: RichField + Extendable<D>>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        self.repeated_frobenius(1, builder)
    }

    pub fn repeated_frobenius<F: RichField + Extendable<D>>(
        &self,
        count: usize,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        if count == 0 {
            return *self;
        } else if count >= D {
            return self.repeated_frobenius(count % D, builder);
        }
        let arr = self.to_target_array();
        let k = (F::order() - 1u32) / (D as u64);
        let z0 = F::Extension::W.exp_biguint(&(k * count as u64));
        #[allow(clippy::needless_collect)]
        let zs = z0
            .powers()
            .take(D)
            .map(|z| builder.constant(z))
            .collect::<Vec<_>>();

        let mut res = Vec::with_capacity(D);
        for (z, a) in zs.into_iter().zip(arr) {
            res.push(builder.mul(z, a));
        }

        res.try_into().unwrap()
    }

    pub fn from_range(row: usize, range: Range<usize>) -> Self {
        debug_assert_eq!(range.end - range.start, D);
        Target::wires_from_range(row, range).try_into().unwrap()
    }
}

impl<const D: usize> TryFrom<Vec<Target>> for NonnativeTarget<D> {
    type Error = Vec<Target>;

    fn try_from(value: Vec<Target>) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

/// `Target`s representing an element of an extension of an extension field.
#[derive(Copy, Clone, Debug)]
pub struct NonnativeAlgebraTarget<const D: usize>(pub [NonnativeTarget<D>; D]);

impl<const D: usize> NonnativeAlgebraTarget<D> {
    pub fn to_nonnative_target_array(&self) -> [NonnativeTarget<D>; D] {
        self.0
    }
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilder<F, D> {
    pub fn constant_nonnative(&mut self, c: F::Extension) -> NonnativeTarget<D> {
        let c_parts = c.to_basefield_array();
        let mut parts = [self.zero(); D];
        for i in 0..D {
            parts[i] = self.constant(c_parts[i]);
        }
        NonnativeTarget(parts)
    }

    pub fn constant_nonnative_algebra(
        &mut self,
        c: NonnativeAlgebra<F::Extension, D>,
    ) -> NonnativeAlgebraTarget<D> {
        let c_parts = c.to_basefield_array();
        let mut parts = [self.zero_nonnative(); D];
        for i in 0..D {
            parts[i] = self.constant_nonnative(c_parts[i]);
        }
        NonnativeAlgebraTarget(parts)
    }

    pub fn zero_nonnative(&mut self) -> NonnativeTarget<D> {
        self.constant_nonnative(F::Extension::ZERO)
    }

    pub fn one_nonnative(&mut self) -> NonnativeTarget<D> {
        self.constant_nonnative(F::Extension::ONE)
    }

    pub fn two_nonnative(&mut self) -> NonnativeTarget<D> {
        self.constant_nonnative(F::Extension::TWO)
    }

    pub fn neg_one_nonnative(&mut self) -> NonnativeTarget<D> {
        self.constant_nonnative(F::Extension::NEG_ONE)
    }

    pub fn zero_nonnative_algebra(&mut self) -> NonnativeAlgebraTarget<D> {
        self.constant_nonnative_algebra(NonnativeAlgebra::ZERO)
    }

    pub fn convert_to_nonnative(&mut self, t: Target) -> NonnativeTarget<D> {
        let zero = self.zero();
        t.to_nonnative_target(zero)
    }

    pub fn convert_to_nonnative_algebra(&mut self, et: NonnativeTarget<D>) -> NonnativeAlgebraTarget<D> {
        let zero = self.zero_nonnative();
        let mut arr = [zero; D];
        arr[0] = et;
        NonnativeAlgebraTarget(arr)
    }
}

/// Flatten the slice by sending every extension target to its D-sized canonical representation.
pub fn flatten_target<const D: usize>(l: &[NonnativeTarget<D>]) -> Vec<Target> {
    l.iter()
        .flat_map(|x| x.to_target_array().to_vec())
        .collect()
}

/// Batch every D-sized chunks into extension targets.
pub fn unflatten_target<F: RichField + Extendable<D>, const D: usize>(
    l: &[Target],
) -> Vec<NonnativeTarget<D>> {
    debug_assert_eq!(l.len() % D, 0);
    l.chunks_exact(D)
        .map(|c| c.to_vec().try_into().unwrap())
        .collect()
}
