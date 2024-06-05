use ark_pcs_bench_templates::*;
use ark_poly::DenseUVPolynomial;
use blake2::Blake2s256;

use ark_ed_on_bls12_381::{EdwardsAffine, Fr};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial as DenseUnivariatePoly;
use ark_poly_commit::ipa_pc::InnerProductArgPC;

use rand_chacha::ChaCha20Rng;

type UniPoly = DenseUnivariatePoly<Fr>;
type PC<E, D, P> = InnerProductArgPC<E, D, P>;

// IPA_PC over the JubJub curve with Blake2s as the hash function
#[allow(non_camel_case_types)]
type IPA_JubJub = PC<EdwardsAffine, Blake2s256, UniPoly>;

fn rand_poly_ipa_pc<F: PrimeField>(degree: usize, rng: &mut ChaCha20Rng) -> DenseUnivariatePoly<F> {
    DenseUnivariatePoly::rand(degree, rng)
}

const MIN_DEGREE: usize = 10;
const MAX_DEGREE: usize = 20;

fn main() {
    println!("\nIPA on JubJub: Commitment size");
    for degree in (MIN_DEGREE..MAX_DEGREE).step_by(2) {
        println!(
            "\tdegree: {}, size: {} B",
            degree,
            commitment_size::<_, _, IPA_JubJub>(degree, rand_poly_ipa_pc)
        );
    }

    println!("\nIPA on JubJub: Proof size");
    for degree in (MIN_DEGREE..MAX_DEGREE).step_by(2) {
        println!(
            "\tdegree: {}, size: {} B",
            degree,
            proof_size::<_, _, IPA_JubJub>(degree, rand_poly_ipa_pc, rand_uv_point)
        );
    }
}
