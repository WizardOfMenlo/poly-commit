use ark_pcs_bench_templates::*;
use ark_poly::DenseMultilinearExtension;

use ark_bn254::{Fr, G1Affine};
use ark_poly_commit::hyrax::HyraxPC;

// Hyrax PCS over BN254
type Hyrax254 = HyraxPC<G1Affine, DenseMultilinearExtension<Fr>>;

const MIN_NUM_VARS: usize = 24;
const MAX_NUM_VARS: usize = 24;

bench!(Hyrax254, rand_ml_poly, rand_ml_point);
