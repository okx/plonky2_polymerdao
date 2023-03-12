use anyhow::Result;
use plonky2::field::goldilocks_field::GoldilocksField as GF;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::hashing;
use plonky2::hash::poseidon::{PoseidonHash, PoseidonPermutation};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::hash::hash_types::RichField;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::Target;
use plonky2::iop::target::BoolTarget;
use plonky2_field::extension::Extendable;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};


// The use below may not be required
// use plonky2::plonk::hash::PoseidonHash;

/// An example of Membership verification in Merkle tree of height 4
/// input field element a, hash values h0, h1, h2, merkle tree rooot value mtr

pub struct MerkleMembershipProofTargets {
    pub proof_subject: Target,
    pub proof_subject_index: Target,
    pub merkle_tree_path: Vec<HashOutTarget>,
    pub proof_verification_result: BoolTarget,
}

pub fn make_circuits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    merkle_tree_hight: u32,
) -> MerkleMembershipProofTargets {
    // type C = PoseidonGoldilocksConfig;
    // type Hasher = <C as GenericConfig<D>>::Hasher;

    let proof_subject = builder.add_virtual_target();
    let proof_subject_index = builder.add_virtual_target();
    let mut merkle_tree_path = Vec::new();

    let aux = vec![proof_subject];
    let mut aux = builder.hash_n_to_hash_no_pad::<PoseidonHash>(aux);

    for i in 0..merkle_tree_hight {
        merkle_tree_path.push(builder.add_virtual_hash());
        // let ith_bit = builder.and(proof_subject_index, GF(1 << i));
        if i < merkle_tree_hight - 1 {
            // let targets = [aux.elements, merkle_tree_path[i].elements].concat();
            let targets = [aux.elements, merkle_tree_path.last().unwrap().elements].concat();
            aux = builder.hash_n_to_hash_no_pad::<PoseidonHash>(targets);
        }
    }

    let result0 = builder.is_equal(aux.elements[0], merkle_tree_path.last().unwrap().elements[0]);
    let result1 = builder.is_equal(aux.elements[1], merkle_tree_path.last().unwrap().elements[1]);
    let result2 = builder.is_equal(aux.elements[2], merkle_tree_path.last().unwrap().elements[2]);
    let result3 = builder.is_equal(aux.elements[3], merkle_tree_path.last().unwrap().elements[3]);
    let result01 = builder.and(result0, result1);
    let result23 = builder.and(result2, result3);
    let proof_verification_result = builder.and(result01, result23);

    MerkleMembershipProofTargets {
        proof_subject,
        proof_subject_index,
        merkle_tree_path,
        proof_verification_result,
    }
}

pub fn make_verify_circuits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    merkle_tree_hight: u32,
) -> MerkleMembershipProofTargets {

    let MerkleMembershipProofTargets {
        proof_subject,
        proof_subject_index,
        merkle_tree_path,
        proof_verification_result,
    } = make_circuits(builder, merkle_tree_hight);

    builder.register_public_input(proof_subject);

    // builder.register_public_input(proof_subject_index);

    for h in &merkle_tree_path {
        builder.register_public_inputs(&h.elements);
    }

    builder.register_public_input(proof_verification_result.target);

    MerkleMembershipProofTargets {
        proof_subject,
        proof_subject_index,
        merkle_tree_path,
        proof_verification_result,
    }
}

pub fn fill_circuits<F: RichField + Extendable<D>, const D: usize>(
    pw: &mut PartialWitness<F>,
    proof_subject_val: F,
    // proof_subject_index_val: u32,
    merkle_tree_path_val: &Vec<Box<Vec<F>>>,
    targets: MerkleMembershipProofTargets,
) {

    let MerkleMembershipProofTargets {
        proof_subject,
        proof_subject_index,
        merkle_tree_path,
        proof_verification_result,
    } = targets;

    assert_eq!(merkle_tree_path.len(), merkle_tree_path_val.len());

    pw.set_target(proof_subject, proof_subject_val);

    for i in 0..merkle_tree_path.len() {
        pw.set_hash_target(merkle_tree_path[i], HashOut::from_vec(*merkle_tree_path_val[i].clone()));
    }
}

pub fn build_merkle_tree_path_val<F: RichField + Extendable<D>, const D: usize>(
    value: F,
    sibling_hash_val: Vec<&[F]>,
) -> Vec<Box<Vec<F>>> {
    let aux = vec![value];
    let mut aux = hashing::hash_n_to_m_no_pad::<F, PoseidonPermutation>(&aux, 4);

    let mut v = Vec::new();

    for shv in sibling_hash_val {
        v.push(Box::new(shv.to_vec()));
        let elements = [aux, shv.to_vec()].concat();
        aux = hashing::hash_n_to_m_no_pad::<F, PoseidonPermutation>(&elements, 4);
    }

    v.push(Box::new(aux));

    v
}

fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    // type Hasher = <C as GenericConfig<D>>::Hasher;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let proof_subject = GF(0x12345678);
    let merkle_tree_path_raw_data =
        vec![
            &[GF(15612627474000122082), GF(14060194962823407015), GF(850778232954936903),  GF(9947949590738376399)] as &[F],
            &[GF(15612627474000122082), GF(14060194962823407015), GF(850778232954936903),  GF(9947949590738376399)] as &[F],
        ];

    let merkle_tree_path_val = build_merkle_tree_path_val::<F, D>(proof_subject, merkle_tree_path_raw_data);

    let merkle_tree_hight = merkle_tree_path_val.len() as u32;

    let targets = make_verify_circuits(
        &mut builder,
        merkle_tree_hight
    );

    // Provide initial values.
    let mut pw = PartialWitness::<GF>::new();

    fill_circuits::<F, D>(
        &mut pw,
        proof_subject,
        &merkle_tree_path_val,
        targets,
    );

    let data = builder.build::<C>();
    let proof = data.prove(pw)?;

    // for i in 1..9 {
        // println!("proof.public_inputs[{i}] = {}", proof.public_inputs[i as usize]);
    // }

    let result_idx = 1 + merkle_tree_hight * 4;
    // assert_eq!(proof.public_inputs[5..9], proof.public_inputs[9..13]);
    assert_eq!(result_idx, 13);
    assert_eq!(proof.public_inputs[result_idx as usize], GF(1));

    println!("proof.public_inputs[{result_idx}] = {}", proof.public_inputs[result_idx as usize]);

    data.verify(proof)
}
