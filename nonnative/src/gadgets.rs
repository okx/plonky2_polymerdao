use plonky2::field::extension::Extendable;
use plonky2::field::types::{Field, PrimeField};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;
use plonky2_ecdsa::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
use plonky2_u32::gadgets::arithmetic_u32::U32Target;

use crate::gates::MulNonNativeGate;

pub trait NonNativeAritmetic<F: RichField + Extendable<D>, const D: usize> {

    fn mul_nonnative_gate<FF: PrimeField>(
        &mut self,
        multiplicand_0: NonNativeTarget<FF>,
        multiplicand_1: NonNativeTarget<FF>,
    ) -> NonNativeTarget<FF>;
}

impl<F: RichField + Extendable<D>, const D: usize> NonNativeAritmetic<F, D> for CircuitBuilder<F, D> {
    fn mul_nonnative_gate<FF: PrimeField>(
        &mut self,
        multiplicand_0: NonNativeTarget<FF>,
        multiplicand_1: NonNativeTarget<FF>,
    ) -> NonNativeTarget<FF> {

        let num_limbs   = Self::num_nonnative_limbs::<FF>();
        let num_limbs_0 = multiplicand_0.value.num_limbs();
        let num_limbs_1 = multiplicand_1.value.num_limbs();

        assert_eq!(num_limbs, num_limbs_0);
        assert_eq!(num_limbs, num_limbs_1);

        let gate = MulNonNativeGate::new(num_limbs);
        let row = self.add_gate(gate, vec![]);

        let wires_multiplicand_0 = vec![];

        for i in 0..num_limbs {
            wires_multiplicand_0.push(U32Target(Target::wire(row, gate.wire_ith_limb_of_multiplicand_0(i))));
        }

        let m_0 = self.biguint_to_nonnative(&BigUintTarget{limbs: wires_multiplicand_0});

        let wires_multiplicand_1 = vec![];

        for i in 0..num_limbs {
            wires_multiplicand_1.push(U32Target(Target::wire(row, gate.wire_ith_limb_of_multiplicand_1(i))));
        }

        let m_1 = self.biguint_to_nonnative(&BigUintTarget{limbs: wires_multiplicand_1});

        self.connect_nonnative(&multiplicand_0, &m_0);
        self.connect_nonnative(&multiplicand_1, &m_1);

        let wires_product = vec![];

        for i in 0..num_limbs*2 {
            wires_product.push(U32Target(Target::wire(row, gate.wire_ith_limb_of_output(i))));
        }

        self.biguint_to_nonnative(&BigUintTarget{limbs: wires_product})
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use num::bigint::BigUint;
    // use plonky2::field::types::Sample;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig}; 

    use plonky2::field::secp256k1_base::Secp256K1Base;

    use super::*;

    #[test]
    fn test_gadget() -> Result<()> {
        type FF = Secp256K1Base;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let x_ff = FF::from_noncanonical_biguint(BigUint::from_slice(&[
            0x11111111,
            0x11111111,
            0x11111111,
            0x11111111,
            0x11111111,
            0x11111111,
            0x11111111,
            0x11111111,
        ]));
        let y_ff = FF::from_noncanonical_biguint(BigUint::from_slice(&[
            0x00000002,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
        ]));
        let product_ff = x_ff * y_ff;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative(x_ff);
        let y = builder.constant_nonnative(y_ff);
        // let product = builder.mul_nonnative(&x, &y);
        let product = builder.mul_nonnative_gate(x, y);

        let product_expected = builder.constant_nonnative(product_ff);
        builder.connect_nonnative(&product, &product_expected);

        dbg!(builder.num_gates());
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }
}
