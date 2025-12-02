#![allow(dead_code)]

use merkletree::merkle::MerkleTree;
use merkletree::store::VecStore;
use merkletree::hash::Algorithm;
use sha2::{Digest, Sha256};
use reth_trie::{TrieAccount, HashedPostState};
use alloy_primitives::{keccak256, Address};
use std::collections::BTreeMap;
use reth_primitives_traits::Account;
use hex;
use crate::slurachain_vm::AccountState;

pub type MerkleHash = [u8; 32];

/// Algorithme SHA-256 pour MerkleTree (compatible 0.23.0)
#[derive(Clone, Default)]
pub struct Sha256Algorithm(Sha256);

impl std::hash::Hasher for Sha256Algorithm {
    fn write(&mut self, bytes: &[u8]) { self.0.update(bytes); }
    fn finish(&self) -> u64 { 0 }
}

impl Algorithm<MerkleHash> for Sha256Algorithm {
    fn leaf(&mut self, leaf: MerkleHash) -> MerkleHash {
        let mut hasher = Sha256::new();
        hasher.update(&leaf);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    fn node(&mut self, left: MerkleHash, right: MerkleHash, _height: usize) -> MerkleHash {
        let mut hasher = Sha256::new();
        hasher.update(&left);
        hasher.update(&right);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    fn hash(&mut self) -> MerkleHash {
        let mut hasher = Sha256::new();
        hasher.update(&self.0.clone().finalize());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// Merkle Tree SHA-256 à partir de données brutes
pub fn build_merkle_tree(leaves: Vec<Vec<u8>>) -> MerkleTree<MerkleHash, Sha256Algorithm, VecStore<MerkleHash>> {
    let leaf_hashes: Vec<MerkleHash> = leaves
        .into_iter()
        .map(|data| {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        })
        .collect();

    MerkleTree::new(leaf_hashes).expect("REASON")
}

/// Racine du Merkle Tree
pub fn get_merkle_root(tree: &MerkleTree<MerkleHash, Sha256Algorithm, VecStore<MerkleHash>>) -> MerkleHash {
    tree.root()
}

/// Conversion VM -> TrieAccount (adaptée à alloy_trie/reth_trie)
fn to_trie_account(account: &AccountState) -> Account {
    Account {
        nonce: account.nonce,
        balance: alloy_primitives::U256::from(account.balance),
        bytecode_hash: hex::decode(&account.code_hash)
            .ok()
            .and_then(|v| {
                if v.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&v);
                    Some(arr.into())
                } else {
                    None
                }
            }),
    }
}

/// Construit un Patricia Merkle Trie Ethereum-style à partir de l’état VM
pub fn build_state_trie(accounts: &BTreeMap<String, AccountState>) -> HashedPostState {
    let hashed_accounts = accounts.iter().map(|(addr, account)| {
        // Conversion de l'adresse en B256
        let address_bytes = hex::decode(addr.trim_start_matches("0x")).expect("hex decode");
        let mut address_arr = [0u8; 32];
        let len = address_bytes.len().min(32);
        address_arr[32 - len..].copy_from_slice(&address_bytes[..len]);
        let address = alloy_primitives::B256::from(address_arr);

        // Conversion du code_hash en Option<B256>
        let bytecode_hash = hex::decode(&account.code_hash)
            .ok()
            .and_then(|v| {
                if v.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&v);
                    Some(arr.into())
                } else {
                    None
                }
            });

        let account_obj = reth_primitives_traits::account::Account {
            nonce: account.nonce,
            balance: alloy_primitives::U256::from(account.balance),
            bytecode_hash,
        };
        (address, Some(account_obj))
    });

    reth_trie::HashedPostState::default().with_accounts(hashed_accounts)
}