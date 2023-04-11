use core::ops::Range;
use num::bigint::BigUint;
// use ::slice_of_array::prelude::*;

// use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::extension::{Extendable, flatten, unflatten};
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::{ExtensionTarget, flatten_target};
use plonky2::plonk::vars::{EvaluationVars, EvaluationVarsBase, EvaluationTargets};

// use plonky2_ecdsa::gadgets::biguint::{CircuitBuilderBiguint, BigUintTarget};
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;
use plonky2_u32::gadgets::arithmetic_u32::U32Target;

////////////////////////////////////////////////////////////////////////////////

pub trait FieldExtToBigUint {
    fn get_local_biguint_algebra(
        &self,
        wire_range: Range<usize>,
    ) -> BigUint;
}

impl<'a, F: RichField + Extendable<D>, const D: usize> FieldExtToBigUint for EvaluationVars<'a, F, D> {
    fn get_local_biguint_algebra(
        &self,
        wire_range: Range<usize>,
    ) -> BigUint {
        let arr: &[F::Extension] = self.local_wires[wire_range].try_into().unwrap();
        let values = flatten::<F, D>(arr).iter().map(|v| v.to_canonical_u64() as u32).collect();
        BigUint::new(values)
    }
}

pub trait BigUintToVecFieldExt<F: RichField + Extendable<D>, const D: usize> {
    fn to_basefield_array(
        &self,
    ) -> Vec<F::Extension>;
}

impl<F: RichField + Extendable<D>, const D: usize> BigUintToVecFieldExt<F, D> for BigUint {
    fn to_basefield_array(
        &self,
    ) -> Vec<F::Extension> {
        let mut u32_digits = self.to_u32_digits();

        let res = u32_digits.len() % D;

        if res != 0 {
            for _ in 0..D-res {
                u32_digits.push(0u32);
            }
        }

        let aux: Vec<F> = u32_digits.into_iter().map(|d| F::from_canonical_u32(d)).collect();

        unflatten(&aux)
    }
}

////////////////////////////////////////////////////////////////////////////////

pub trait FieldToBigUint {
    fn get_local_biguint(
        &self,
        wire_range: Range<usize>,
    ) -> BigUint;
}

impl<'a, F: RichField> FieldToBigUint for EvaluationVarsBase<'a, F> {
    fn get_local_biguint(
        &self,
        wire_range: Range<usize>,
    ) -> BigUint {
        let arr: Vec<u32> = wire_range.map(|i| self.local_wires[i].to_canonical_u64() as u32).collect();
        BigUint::new(arr)
    }
}

pub trait BigUintToVecField<F: Field> {
    fn to_basefield_array(
        &self,
    ) -> Vec<F>;
}

impl<F: Field> BigUintToVecField<F> for BigUint {
    fn to_basefield_array(
        &self,
    ) -> Vec<F> {
        let u32_digits = self.to_u32_digits();

        u32_digits.into_iter().map(|a| F::from_canonical_u32(a)).collect()
    }
}

////////////////////////////////////////////////////////////////////////////////

pub trait FieldExtTargetsToBigUintTarget {
    fn get_local_biguint_algebra(
        &self,
        wire_range: Range<usize>,
    ) -> BigUintTarget;
}

impl<'a, const D: usize> FieldExtTargetsToBigUintTarget for EvaluationTargets<'a, D> {
    fn get_local_biguint_algebra(
        &self,
        wire_range: Range<usize>,
    ) -> BigUintTarget {
        let arr: &[ExtensionTarget<D>] = self.local_wires[wire_range].try_into().unwrap();
        let limbs = flatten_target::<D>(arr).into_iter().map(|t| U32Target(t)).collect();
        BigUintTarget{ limbs }
    }
}

pub trait BigUintTargetToVecFieldExtTargets<const D: usize> {
    fn to_ext_target_array(
        &self,
    ) -> Vec<ExtensionTarget<D>>;
}

impl<const D: usize> BigUintTargetToVecFieldExtTargets<D> for BigUintTarget {
    fn to_ext_target_array(
        &self,
    ) -> Vec<ExtensionTarget<D>> {
        todo!()
    }
}
