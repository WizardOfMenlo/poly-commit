use ark_pcs_bench_templates::*;
use ark_poly::multivariate::{SparsePolynomial, SparseTerm};

use ark_bn254::{Bn254, Fr};
use ark_poly_commit::marlin_pst13_pc::MarlinPST13;

// Hyrax PCS over BN254
type PST13Bn254 = MarlinPST13<Bn254, SparsePolynomial<Fr, SparseTerm>>;

const MIN_NUM_VARS: usize = 24;
const MAX_NUM_VARS: usize = 24;

bench!(PST13Bn254, rand_sparse_ml_poly, rand_ml_point);
