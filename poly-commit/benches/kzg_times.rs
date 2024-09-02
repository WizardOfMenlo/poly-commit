use ark_ec::pairing::Pairing;
use ark_pcs_bench_templates::*;

use ark_bls12_381::Bls12_381;
use ark_poly::univariate::DensePolynomial as DenseUnivariatePoly;
use ark_poly_commit::marlin_pc::MarlinKZG10;

type UniPoly = DenseUnivariatePoly<<Bls12_381 as Pairing>::ScalarField>;

// KZG over BN254
#[allow(non_camel_case_types)]
type KZG_BLS381 = MarlinKZG10<Bls12_381, UniPoly>;

const MIN_NUM_VARS: usize = 24;
const MAX_NUM_VARS: usize = 25;

bench!(KZG_BLS381, rand_uv_poly, rand_uv_point);
