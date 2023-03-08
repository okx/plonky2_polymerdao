use core::iter::zip;
use anyhow::Result;
use plonky2::field::types::{Field, Sample};
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
// use crate::plonk::config::{AlgebraicHasher, GenericConfig};


// The use below may not be required
// use plonky2::plonk::hash::PoseidonHash;

/// An example of Membership verification in Merkle tree of height 4
/// input field element a, hash values h0, h1, h2, merkle tree rooot value mtr

fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // The arithmetic circuit.
    let initial_a = builder.add_virtual_target();

    let initial_h0 = builder.add_virtual_hash();
    let initial_h1 = builder.add_virtual_hash();
    let initial_h2 = builder.add_virtual_hash();
    let h = vec![initial_h0, initial_h1, initial_h2];

    let initial_mtr = builder.add_virtual_hash();

    let aux = vec![initial_a];
    let mut aux = builder.hash_n_to_hash_no_pad::<<PoseidonGoldilocksConfig as GenericConfig<D>>::Hasher>(aux);

    for i in 0..h.len() {
        aux = builder.hash_n_to_hash_no_pad::<<PoseidonGoldilocksConfig as GenericConfig<D>>::Hasher>(
            [
                aux.elements,
                h[i].elements
            ].concat()
        );
    }

    let mut result = true;

    for (x, y) in zip(initial_mtr.elements, aux.elements) {
        result &= x == y;
    }

    // Public inputs are the two initial values (provided below) and the result (which is generated).
    builder.register_public_input(initial_a);
    builder.register_public_inputs(&initial_h0.elements);
    builder.register_public_inputs(&initial_h1.elements);
    builder.register_public_inputs(&initial_h2.elements);
    builder.register_public_inputs(&initial_mtr.elements);

    // builder.register_public_input(result);

    // Provide initial values.
    let mut pw = PartialWitness::new();
    pw.set_target(initial_a, F::ZERO);

    let h0: HashOut<F> = HashOut::rand(); // rand() is not good here!; how to calc hash values ?
    pw.set_hash_target(initial_h0, h0);
    let h1: HashOut<F> = HashOut::rand(); // rand() is not good here!; how to calc hash values ?
    pw.set_hash_target(initial_h1, h1);
    let h2: HashOut<F> = HashOut::rand(); // rand() is not good here!; how to calc hash values ?
    pw.set_hash_target(initial_h2, h2);

    let mtr: HashOut<F> = HashOut::rand(); // rand() is not good here!; how to calc hash values ?
    pw.set_hash_target(initial_mtr, mtr);

    // pw.set_target(result, F::ONE);

    let data = builder.build::<C>();
    let proof = data.prove(pw)?;

    for i in 0..aux.elements.len() {
        println!("aux[{i}] = {:?}", aux.elements[i]);
    }

    println!("Merkle root verification result is: {}", result);

    data.verify(proof)
}
