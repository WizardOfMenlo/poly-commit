use ark_pcs_bench_templates::*;
use blake2::Blake2s256;

use ark_ed_on_bls12_381::{EdwardsAffine, Fr};
use ark_poly::univariate::DensePolynomial as DenseUnivariatePoly;
use ark_poly_commit::ipa_pc::InnerProductArgPC;

type UniPoly = DenseUnivariatePoly<Fr>;

// IPA_PC over the JubJub curve with Blake2s as the hash function
#[allow(non_camel_case_types)]
type IPA_JubJub = InnerProductArgPC<EdwardsAffine, Blake2s256, UniPoly>;

const MIN_NUM_VARS: usize = 10;
const MAX_NUM_VARS: usize = 20;

bench!(IPA_JubJub, rand_uv_poly, rand_uv_point);
