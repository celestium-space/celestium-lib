use crate::{
    serialize::{DynamicSized, Serialize},
    transaction::TransactionBlock,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const HASH_SIZE: usize = 32;

struct Node {
    left: [u8; HASH_SIZE],
    right: [u8; HASH_SIZE],
}

impl Node {
    pub fn serialize(&self) -> [u8; HASH_SIZE * 2] {
        let serialized = [0; HASH_SIZE * 2];
        serialized[0..HASH_SIZE].copy_from_slice(&self.left);
        serialized[HASH_SIZE..HASH_SIZE * 2].copy_from_slice(&self.right);
        serialized
    }

    pub fn hash(&self) -> [u8; HASH_SIZE] {
        let hash = [0; HASH_SIZE];
        hash.copy_from_slice(Sha256::digest(&self.serialize()).as_slice());
        hash
    }
}

pub struct MerkleForest<T> {
    leafs: HashMap<[u8; HASH_SIZE], T>,
    nodes: HashMap<[u8; HASH_SIZE], Node>,
}

impl MerkleForest<TransactionBlock> {
    pub fn from_serialized_transactions(
        data: &[u8],
        i: &mut usize,
        users: &mut HashMap<secp256k1::PublicKey, crate::user::User>,
    ) -> Result<Self, String> {
        let leafs: HashMap<[u8; HASH_SIZE], TransactionBlock> = HashMap::new();
        while *i < data.len() {
            let transaction = *TransactionBlock::from_serialized(&data, &mut i, users)?;
            leafs.insert(transaction.hash()?, transaction);
        }
        Ok(MerkleForest {
            leafs,
            nodes: HashMap::new(),
        })
    }

    pub fn add_serialized_nodes(&self, data: &[u8]) -> Result<bool, String> {
        if data.len() % HASH_SIZE * 2 != 0 {
            return Err(format!(
                "Data lenght {} is not devidable with node size of {}",
                data.len(),
                HASH_SIZE * 2
            ));
        }
        for chunk in data.chunks(HASH_SIZE * 2) {
            let left = [0; HASH_SIZE];
            let right = [0; HASH_SIZE];
            left.copy_from_slice(&chunk[0..HASH_SIZE]);
            right.copy_from_slice(&data[HASH_SIZE..HASH_SIZE * 2]);
            let node = Node { left, right };
            self.nodes.insert(node.hash(), node);
        }
        Ok(true)
    }

    pub fn add_serialized_transactions(
        &mut self,
        data: &[u8],
        users: &mut HashMap<secp256k1::PublicKey, crate::user::User>,
    ) -> Result<Vec<TransactionBlock>, String> {
        let mut transactions = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let pre_i = i;
            let mut hash = [0; 32];
            hash.copy_from_slice(Sha256::digest(&data[pre_i..i]).as_slice());
            self.leafs.insert(
                hash,
                *TransactionBlock::from_serialized(&data, &mut i, users)?,
            );
            transactions.push(*TransactionBlock::from_serialized(&data, &mut i, users)?);
        }
        Ok(transactions)
    }

    fn serialize_all_transactions(&self) -> Result<Vec<u8>, String> {
        let mut transaction_len = 0;
        for (_, transaction) in self.leafs.iter() {
            transaction_len += transaction.serialized_len();
        }
        let mut serialized = vec![0; transaction_len];
        let mut i = 0;
        for (_, transaction) in self.leafs.iter() {
            transaction.serialize_into(&mut serialized, &mut i)?;
        }
        Ok(serialized)
    }

    fn serialize_all_nodes(&self) -> Result<Vec<u8>, String> {
        let serialized = vec![0; self.nodes.len() * HASH_SIZE * 2];
        let i = 0;
        for node in self.nodes {
            serialized[i..HASH_SIZE].copy_from_slice(&node.1.serialize());
        }
        Ok(serialized)
    }

    fn get_transactions(
        &self,
        hashes: Vec<[u8; 32]>,
    ) -> Result<Vec<TransactionBlock>, (Vec<TransactionBlock>, Vec<[u8; 32]>)> {
        let missing = Vec::new();
        let found = Vec::new();
        for hash in hashes {
            match self.leafs.get(&hash) {
                Some(leaf) => found.push(*leaf),
                None => missing.push(hash),
            }
        }
        if missing.len() > 0 {
            Err((found, missing))
        } else {
            Ok(found)
        }
    }

    fn is_ancestor(
        &self,
        decendant: TransactionBlock,
        ancestor: [u8; 32],
    ) -> Result<TransactionBlock, Vec<[u8; 32]>> {
        let current_hash = ancestor;
        let tmp_node = self.nodes.get(&current_hash);
        match tmp_node {
            Some(node) => {
                let errs;
                match self.is_ancestor(decendant, node.left) {
                    Ok(left) => return Ok(left),
                    Err(e) => errs = e,
                };
                match self.is_ancestor(decendant, node.right) {
                    Ok(right) => return Ok(right),
                    Err(e) => errs.append(&mut e),
                };
                Err(errs)
            }
            None => match self.leafs.get(&current_hash) {
                Some(result) => Ok(*result),
                None => Err(vec![current_hash]),
            },
        }
    }

    // fn un_rooted_leafs(&self, known_roots) -> Vec<TransactionBlock> {

    // }

    // fn get<TransactionBlock>(&self, hash: [u8; HASH_SIZE]) -> Option<&TransactionBlock> {
    //     self.leafs.get(&hash)
    // }

    // fn get<Node>(&self, hash: [u8; HASH_SIZE]) -> Option<Node> {
    //     self.nodes.get(hash)
    // }

    fn is_complete(&self, root: [u8; HASH_SIZE]) -> Result<usize, String> {
        let found_node = self.nodes.get(&root);
        let found_leaf = self.leafs.get(&root);
        match (found_node, found_leaf) {
            (Some(found_node), None) => {
                let left_len = self.is_complete(found_node.left)?;
                let right_len = self.is_complete(found_node.right)?;
                if left_len == right_len {
                    Ok(left_len + 1)
                } else {
                    Err("Unbalanced Merkle tree".to_string())
                }
            }
            (None, Some(found_leaf)) => Ok(0),
            _ => Err(format!("Missing node with hash {:?}", root)),
        }
    }
}
