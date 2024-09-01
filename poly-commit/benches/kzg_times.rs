use ark_ec::pairing::Pairing;
use ark_pcs_bench_templates::*;

use ark_bn254::Bn254;
use ark_poly::univariate::DensePolynomial as DenseUnivariatePoly;
use ark_poly_commit::marlin_pc::MarlinKZG10;

type UniPoly = DenseUnivariatePoly<<Bn254 as Pairing>::ScalarField>;

// KZG over BN254
#[allow(non_camel_case_types)]
type KZG_BN254 = MarlinKZG10<Bn254, UniPoly>;

const MIN_NUM_VARS: usize = 24;
const MAX_NUM_VARS: usize = 25;

bench!(KZG_BN254, rand_uv_poly, rand_uv_point);
