use merkle_light::merkle::{MerkleTree, FromIndexedParallelIterator};
use sha2::{Sha256, Digest};

pub type Hash = [u8; 32];

pub fn hash_leaf(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn build_merkle_tree(leaves: Vec<Vec<u8>>) -> MerkleTree<Hash, Sha256> {
    MerkleTree::from_iter(leaves.into_iter().map(|leaf| hash_leaf(&leaf)))
}

pub fn get_root(tree: &MerkleTree<Hash, Sha256>) -> Hash {
    *tree.root()
}