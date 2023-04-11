use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecdsa::gadgets::biguint::{BigUintTarget, CircuitBuilderBiguint, WitnessBigUint};
use plonky2_u32::gadgets::arithmetic_u32::U32Target;

use crate::gates::biguint::MulBigUintGate;

pub trait BigUintAritmetic<F: RichField + Extendable<D>, const D: usize> {

    fn mul_biguint_gate(
        &mut self,
        multiplicand_0: &BigUintTarget,
        multiplicand_1: &BigUintTarget,
    ) -> BigUintTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> BigUintAritmetic<F, D> for CircuitBuilder<F, D> {
    fn mul_biguint_gate(
        &mut self,
        multiplicand_0: &BigUintTarget,
        multiplicand_1: &BigUintTarget,
    ) -> BigUintTarget {

        let gate = MulBigUintGate::new(multiplicand_0.num_limbs(), multiplicand_1.num_limbs());
        let row = self.add_gate(gate, vec![]);

        let limbs: Vec<U32Target> = gate
                                    .wires_multiplicand_0()
                                    .map(|i| U32Target(Target::wire(row, i)))
                                    .collect();

        self.connect_biguint(&multiplicand_0, &BigUintTarget{limbs});

        let limbs: Vec<U32Target> = gate
                                    .wires_multiplicand_1()
                                    .map(|i| U32Target(Target::wire(row, i)))
                                    .collect();

        self.connect_biguint(&multiplicand_1, &BigUintTarget{limbs});

        let limbs: Vec<U32Target> = gate
                                    .wires_output()
                                    .map(|i| U32Target(Target::wire(row, i)))
                                    .collect();

        BigUintTarget{limbs}
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use num::bigint::BigUint;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig}; 

    use super::*;

    #[test]
    fn test_biguint_gadget() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let x_value = BigUint::from_slice(&[
            0x00000003,
        ]);
        let y_value = BigUint::from_slice(&[
            0x00000005,
        ]);
        let expected_z_value = &x_value * &y_value;

        let config = CircuitConfig::standard_ecc_config();

        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_biguint_target(x_value.to_u32_digits().len());
        let y = builder.add_virtual_biguint_target(y_value.to_u32_digits().len());
        // let z = builder.mul_biguint(&x, &y);
        let z = builder.mul_biguint_gate(&x, &y);
        let expected_z = builder.add_virtual_biguint_target(expected_z_value.to_u32_digits().len());
        builder.connect_biguint(&z, &expected_z);

        pw.set_biguint_target(&x, &x_value);
        pw.set_biguint_target(&y, &y_value);
        pw.set_biguint_target(&expected_z, &expected_z_value);

        dbg!(builder.num_gates());
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }
}
