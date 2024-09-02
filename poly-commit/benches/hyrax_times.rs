use ark_pcs_bench_templates::*;
use ark_poly::DenseMultilinearExtension;

use ark_bls12_381::{Fr, G1Affine};
use ark_poly_commit::hyrax::HyraxPC;

// Hyrax PCS over BLS381
type HyraxBLS381 = HyraxPC<G1Affine, DenseMultilinearExtension<Fr>>;

const MIN_NUM_VARS: usize = 24;
const MAX_NUM_VARS: usize = 25;

bench!(HyraxBLS381, rand_ml_poly, rand_ml_point);
