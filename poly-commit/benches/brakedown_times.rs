use ark_crypto_primitives::{
    crh::{sha256::Sha256, CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{ByteDigestConverter, Config},
};
use ark_pcs_bench_templates::*;
use ark_poly::DenseMultilinearExtension;

use ark_bn254::Fr;

use ark_poly_commit::linear_codes::{LinearCodePCS, MultilinearBrakedown};
use blake2::Blake2s256;

// Brakedown PCS over BN254
struct MerkleTreeParams;
type LeafH = LeafIdentityHasher;
type CompressH = Sha256;
impl Config for MerkleTreeParams {
    type Leaf = Vec<u8>;

    type LeafDigest = <LeafH as CRHScheme>::Output;
    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
    type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;

    type LeafHash = LeafH;
    type TwoToOneHash = CompressH;
}

pub type MLE<F> = DenseMultilinearExtension<F>;
type MTConfig = MerkleTreeParams;
type ColHasher<F> = FieldToBytesColHasher<F, Blake2s256>;
type Brakedown<F> = LinearCodePCS<
    MultilinearBrakedown<F, MTConfig, MLE<F>, ColHasher<F>>,
    F,
    MLE<F>,
    MTConfig,
    ColHasher<F>,
>;

const MIN_NUM_VARS: usize = 24;
const MAX_NUM_VARS: usize = 24;

bench!(Brakedown<Fr>, rand_ml_poly, rand_ml_point);
