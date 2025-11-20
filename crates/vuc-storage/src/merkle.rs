use merkletree::merkle::MerkleTree;
use merkletree::store::VecStore;
use merkletree::hash::Algorithm;
use sha2::{Digest, Sha256};

pub type MerkleHash = [u8; 32];

#[derive(Default, Clone)]
pub struct Sha256Algorithm(Sha256);

// Removed Hasher trait implementation because it is private.

impl Algorithm<MerkleHash> for Sha256Algorithm {
    fn hash(&mut self) -> MerkleHash {
        let result = self.0.clone().finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    fn reset(&mut self) {
        self.0 = Sha256::new();
    }
    fn leaf(&mut self, leaf: &MerkleHash) -> MerkleHash {
        self.0.update(leaf);
        self.hash()
    }
    fn node(&mut self, left: &MerkleHash, right: &MerkleHash, _height: usize) -> MerkleHash {
        self.0.update(left);
        self.0.update(right);
        self.hash()
    }
}

/// Construit l'arbre Merkle à partir d'une liste de données brutes (Vec<Vec<u8>>)
pub fn build_merkle_tree(leaves: Vec<Vec<u8>>) -> MerkleTree<MerkleHash, Sha256Algorithm, VecStore<MerkleHash>> {
    let leaf_hashes: Vec<MerkleHash> = leaves.into_iter()
        .map(|data| {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hasher.finalize());
            hash
        })
        .collect();
    MerkleTree::from_leaves(&leaf_hashes)
}

/// Récupère la racine de l'arbre
pub fn get_root(tree: &MerkleTree<MerkleHash, Sha256Algorithm, VecStore<MerkleHash>>) -> MerkleHash {
    tree.root()
}