use core::marker::PhantomData;
use core::ops::Range;
// use plonky2::plonk::circuit_data::CircuitConfig;

use plonky2::field::extension::Extendable;
// use plonky2::field::types::{Field, PrimeField};
// use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::gates::gate::Gate;
use plonky2::gates::util::StridedConstraintConsumer;
use plonky2::hash::hash_types::RichField;

use plonky2::iop::ext_target::ExtensionTarget;
// use plonky2::iop::generator::WitnessGenerator;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator, WitnessGenerator};
use plonky2::iop::witness::{PartitionWitness, Witness, WitnessWrite};

use plonky2::iop::target::Target;

use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::vars::{EvaluationVars, EvaluationVarsBase, EvaluationTargets};

// use plonky2_ecdsa::gadgets::biguint::BigUintTarget;
// use plonky2_u32::gadgets::arithmetic_u32::U32Target;

// use plonky2_ecdsa::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};



/// A gate which can perform multiplication, i.e. `result = x y`.
#[derive(Debug, Clone)]
pub struct MulNonNativeGate<F: RichField + Extendable<D>, const D: usize> { 
    pub num_limbs: usize,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> MulNonNativeGate<F, D> {
    pub fn new(num_limbs: usize) -> Self {
        Self {
            num_limbs,
            _phantom: PhantomData,
        }
    }

    pub fn wire_ith_limb_of_multiplicand_0(&self, i: usize) -> usize {
        debug_assert!(i < self.num_limbs);
        i
    }

    pub fn wire_ith_limb_of_multiplicand_1(&self, i: usize) -> usize {
        debug_assert!(i < self.num_limbs);
        self.num_limbs + i
    }

    pub fn wire_ith_limb_of_output(&self, i: usize) -> usize {
        debug_assert!(i < self.num_limbs);
        2 * self.num_limbs + i
    }

    pub fn wires_multiplicand_0(&self) -> Range<usize> {
        0..self.num_limbs
    }

    pub fn wires_multiplicand_1(&self) -> Range<usize> {
        self.num_limbs..self.num_limbs*2
    }

    pub fn wires_ouput(&self) -> Range<usize> {
        self.num_limbs*2..self.num_limbs*4
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Gate<F, D> for MulNonNativeGate<F, D> {
    fn id(&self) -> String {
        format!("{self:?}")
    }

    fn export_circom_verification_code(&self) -> String {
        todo!()
    }

    fn export_solidity_verification_code(&self) -> String {
        todo!()
    }

    fn eval_unfiltered(&self, vars: EvaluationVars<F, D>) -> Vec<F::Extension> {
        let mut constraints = Vec::new();

        let multiplicand_0 = vars.get_local_nonnative_algebra(self.wires_multiplicand_0());
        let multiplicand_1 = vars.get_local_nonnative_algebra(self.wires_multiplicand_1());
        let output = vars.get_local_nonnative_algebra(self.wires_output());
        let computed_output = multiplicand_0 * multiplicand_1;

        constraints.extend((output - computed_output).to_basefield_array());

        constraints
    }

    fn eval_unfiltered_base_one(
        &self,
        vars: EvaluationVarsBase<F>,
        mut yield_constr: StridedConstraintConsumer<F>,
    ) {
        let multiplicand_0 = vars.get_local_nonnative(self.wires_multiplicand_0());
        let multiplicand_1 = vars.get_local_nonnative(self.wires_multiplicand_1());
        let output = vars.get_local_nonnative(self.wires_output());
        let computed_output = multiplicand_0 * multiplicand_1;

        yield_constr.many((output - computed_output).to_basefield_array());
    }

    fn eval_unfiltered_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: EvaluationTargets<D>,
    ) -> Vec<ExtensionTarget<D>> {
        let mut constraints = Vec::new();

        let multiplicand_0 = vars.get_local_nonnative_algebra(self.wires_multiplicand_0());
        let multiplicand_1 = vars.get_local_nonnative_algebra(self.wires_multiplicand_1());
        let output = vars.get_local_nonnative_algebra(self.wires_output());
        let computed_output = builder.mul_nonnative_algebra(multiplicand_0, multiplicand_1);

        let diff = builder.sub_nonnative_algebra(output, computed_output);
        constraints.extend(diff.to_ext_target_array());

        constraints
    }

    fn generators(&self, row: usize, _local_constants: &[F]) -> Vec<Box<dyn WitnessGenerator<F>>> {
        let gen = MulNonNativeGenerator { gate: *self, row };
        vec![Box::new(gen.adapter())]
    }

    fn num_wires(&self) -> usize {
        self.num_limbs * 3
    }

    fn num_constants(&self) -> usize {
        0
    }

    fn degree(&self) -> usize {
        1 /* ? */
    }

    fn num_constraints(&self) -> usize {
        1 /* ? */
    }
}

#[derive(Debug)]
pub struct MulNonNativeGenerator<F: RichField + Extendable<D>, const D: usize> {
    gate: MulNonNativeGate<F, D>,
    row: usize,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F>
    for MulNonNativeGenerator<F, D>
{
    fn dependencies(&self) -> Vec<Target> {
        let num_limbs = self.gate.num_limbs;

        let m0: Vec<Target> = (0..num_limbs)
                                    .map(|i| Target::wire(self.row, self.gate.wire_ith_limb_of_multiplicand_0(i)))
                                    .collect();

        let m1: Vec<Target> = (0..num_limbs)
                                    .map(|i| Target::wire(self.row, self.gate.wire_ith_limb_of_multiplicand_1(i)))
                                    .collect();

        m0.extend(m1);

        m0
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        fn mul_u32(a: u32, b: u32) -> (u32, u32) {
            let a = a as u64;
            let b = b as u64;
            let product = a * b;
            let carry = u32::try_from(product >> 32).unwrap();
            let product = u32::try_from(product & 0xffffffffu64).unwrap();

            (product, carry)
        }

        fn add_u32(a: u32, b: u32) -> (u32, u32) {
            let a = a as u64;
            let b = b as u64;
            let sum = a + b;
            let carry = u32::try_from(sum >> 32).unwrap();
            let sum = u32::try_from(sum & 0xffffffffu64).unwrap();

            (sum, carry)
        }

        fn add_u32s_with_carry(to_add: &[u32], carry: u32) -> (u32, u32) {
            if to_add.len() == 1 {
                return add_u32(to_add[0], carry);
            }

            let to_add: Vec<u64> = (*to_add).iter().map(|v| *v as u64).collect();
            let sum: u64 = to_add.iter().sum();
            let carry = u32::try_from(sum >> 32).unwrap();
            let sum = u32::try_from(sum & 0xffffffffu64).unwrap();

            (sum, carry)
        }

        let num_limbs = self.gate.num_limbs;

        let m0: Vec<u32> = (0..num_limbs)
                                .map(|i| {
                                    witness
                                        .get_target(Target::wire(self.row, self.gate.wire_ith_limb_of_multiplicand_0(i)))
                                        .to_canonical_u64() as u32
                                })
                                .collect();
                                        
        let m1: Vec<u32> = (0..num_limbs)
                                .map(|i| {
                                    witness
                                        .get_target(Target::wire(self.row, self.gate.wire_ith_limb_of_multiplicand_1(i)))
                                        .to_canonical_u64() as u32
                                })
                                .collect();
                                        
        let total_limbs = num_limbs * 2;
        let mut to_add = vec![vec![]; total_limbs];

        for i in 0..num_limbs {
            for j in 0..num_limbs {
                let (product, carry) = mul_u32(m0[i], m1[j]);

                to_add[i + j].push(product);
                to_add[i + j + 1].push(carry);
            }
        }

        let mut limb_values = vec![];
        let mut carry = 0_u32;

        for summands in &mut to_add {
            let (new_product, new_carry) = add_u32s_with_carry(summands, carry);
            limb_values.push(new_product);
            carry = new_carry;
        }

        assert_eq!(carry, 0);

        let size = total_limbs - limb_values.len();

        if size > 0 {
            let aux: Vec<u32> = (0..size).map(|_| 0u32).collect();
            limb_values.extend(aux);
        }

        let output_limbs: Vec<Target> = (0..num_limbs)
                                            .map(|i| Target::wire(self.row, self.gate.wire_ith_limb_of_output(i)))
                                            .collect();

        let output_limb_values: Vec<F> = limb_values.iter().map(|v| F::from_canonical_u32(*v)).collect();

        for (l, v) in output_limbs.iter().zip(output_limb_values) {
            out_buffer.set_target(*l, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    // use num::bigint::BigUint;
    // use plonky2::field::types::Sample;
    // use plonky2::iop::witness::PartialWitness;
    // use plonky2::plonk::circuit_data::CircuitConfig;
    // use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig}; 

    // use plonky2::field::secp256k1_base::Secp256K1Base;

    // use super::*;

    #[test]
    fn test_gate() -> Result<()> {
        todo!()
    }
}
