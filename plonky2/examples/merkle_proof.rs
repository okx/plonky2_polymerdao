use core::iter::zip;
use anyhow::Result;
use plonky2::field::goldilocks_field::GoldilocksField as GF;
use plonky2::field::types::Sample;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::hashing;
// use plonky2::hash::poseidon::{PoseidonHash, PoseidonPermutation};
use plonky2::hash::poseidon::{PoseidonPermutation};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};


// The use below may not be required
// use plonky2::plonk::hash::PoseidonHash;

/// An example of Membership verification in Merkle tree of height 4
/// input field element a, hash values h0, h1, h2, merkle tree rooot value mtr

/*
pub fn make_circuits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> MerkleMembershipProofTargets {
}
*/

fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type Hasher = <C as GenericConfig<D>>::Hasher;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // The arithmetic circuit.
    let initial_a = builder.add_virtual_target();

    let initial_h0 = builder.add_virtual_hash();
    // let initial_h1 = builder.add_virtual_hash();
    // let initial_h2 = builder.add_virtual_hash();
    // let h = vec![initial_h0, initial_h1, initial_h2];
    let h = vec![initial_h0];

    let initial_mtr = builder.add_virtual_hash();
    // let result = builder.add_virtual_bool_target_unsafe();

    let aux = vec![initial_a];
    let mut aux = builder.hash_n_to_hash_no_pad::<Hasher>(aux);

    for i in 0..h.len() {
        aux = builder.hash_n_to_hash_no_pad::<Hasher>(
            [
                aux.elements,
                h[i].elements
            ].concat()
        );
    }

    // let mut result = builder.add_virtual_bool_target_unsafe();
    let result0 = builder.is_equal(aux.elements[0], initial_mtr.elements[0]);
    let result1 = builder.is_equal(aux.elements[1], initial_mtr.elements[1]);
    let result2 = builder.is_equal(aux.elements[2], initial_mtr.elements[2]);
    let result3 = builder.is_equal(aux.elements[3], initial_mtr.elements[3]);
    let result01 = builder.and(result0, result1);
    let result23 = builder.and(result2, result3);
    let result = builder.and(result01, result23);

    // Public inputs are the two initial values (provided below) and the result (which is generated).
    builder.register_public_input(initial_a);
    builder.register_public_inputs(&initial_h0.elements);
    // builder.register_public_inputs(&initial_h1.elements);
    // builder.register_public_inputs(&initial_h2.elements);
    // builder.register_public_inputs(&aux.elements);
    builder.register_public_inputs(&initial_mtr.elements);
    builder.register_public_input(result.target);

    // Provide initial values.
    let mut pw = PartialWitness::new();
    let gf = GF(0x12345678);
    // pw.set_target(initial_a, F::ZERO);
    pw.set_target(initial_a, gf);

    let h_in = vec![gf, GF(0), GF(0), GF(0)];
    let h_out = hashing::hash_n_to_m_no_pad::<F, PoseidonPermutation>(&h_in, 4);
    let h_exp = vec![GF(15612627474000122082), GF(14060194962823407015), GF(850778232954936903), GF(9947949590738376399)];
    assert_eq!(h_exp, h_out);

    // let h0: HashOut<F> = HashOut::from_vec(vec![gf, GF(0), GF(0), GF(0)]);
    let h0: HashOut<F> = HashOut::from_vec(vec![GF(15612627474000122082), GF(14060194962823407015), GF(850778232954936903), GF(9947949590738376399)]);
    let h_out_0 = hashing::hash_n_to_m_no_pad::<F, PoseidonPermutation>(&[HashOut::from_vec(h_out).elements, h0.elements].concat(), 4);
    let h_out_0_exp = vec![GF(2791643930465109725), GF(12981621290817861018), GF(8052271923137798546), GF(11667829020321673470)];
    pw.set_hash_target(initial_h0, h0);
    assert_eq!(h_out_0, h_out_0_exp);

    // let h1: HashOut<F> = HashOut::rand(); // rand() is not good here!; how to calc hash values ?
    // pw.set_hash_target(initial_h1, h1);
    // let h2: HashOut<F> = HashOut::rand(); // rand() is not good here!; how to calc hash values ?
    // pw.set_hash_target(initial_h2, h2);

    let mtr: HashOut<F> = HashOut::from_vec(h_out_0);
    pw.set_hash_target(initial_mtr, mtr);

    let data = builder.build::<C>();
    let proof = data.prove(pw)?;

    // for i in 5..9 {
        // println!("proof.public_inputs[{i}] = {}", proof.public_inputs[i]);
    // }

    // assert_eq!(proof.public_inputs[5..9], proof.public_inputs[9..13]);
    assert_eq!(proof.public_inputs[9], GF(1));

    println!("proof.public_inputs[9] = {}", proof.public_inputs[9]);

    data.verify(proof)
}
