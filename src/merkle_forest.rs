use crate::{
    serialize::{DynamicSized, Serialize},
    transaction::Transaction,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const HASH_SIZE: usize = 32;

#[derive(Clone)]
pub struct Node {
    left: [u8; HASH_SIZE],
    right: [u8; HASH_SIZE],
}

impl Node {
    pub fn new(left: [u8; HASH_SIZE], right: [u8; HASH_SIZE]) -> Self {
        Node { left, right }
    }

    pub fn serialize(&self) -> [u8; HASH_SIZE * 2] {
        let mut serialized = [0; HASH_SIZE * 2];
        serialized[0..HASH_SIZE].copy_from_slice(&self.left);
        serialized[HASH_SIZE..HASH_SIZE * 2].copy_from_slice(&self.right);
        serialized
    }

    pub fn hash(&self) -> [u8; HASH_SIZE] {
        let mut hash = [0; HASH_SIZE];
        hash.copy_from_slice(Sha256::digest(&self.serialize()).as_slice());
        hash
    }
}

#[derive(Clone)]
pub struct MerkleForest<T> {
    leafs: HashMap<[u8; HASH_SIZE], T>,
    branches: HashMap<[u8; HASH_SIZE], Node>,
}

impl MerkleForest<Transaction> {
    pub fn new_empty() -> Self {
        MerkleForest {
            leafs: HashMap::new(),
            branches: HashMap::new(),
        }
    }

    pub fn add_transactions(&mut self, data: Vec<Transaction>) -> Result<bool, String> {
        for transaction in data {
            self.leafs.insert(transaction.hash()?, transaction);
        }
        Ok(true)
    }

    pub fn add_serialized_transactions(
        &mut self,
        data: &[u8],
        i: &mut usize,
        users: &mut HashMap<secp256k1::PublicKey, crate::user::User>,
    ) -> Result<bool, String> {
        while *i < data.len() {
            let transaction = *Transaction::from_serialized(&data, i, users)?;
            self.leafs.insert(transaction.hash()?, transaction);
        }
        Ok(true)
    }

    pub fn add_serialized_nodes(&mut self, data: &[u8]) -> Result<bool, String> {
        if data.len() % HASH_SIZE * 2 != 0 {
            return Err(format!(
                "Data length {} is not devisable with node size of {}",
                data.len(),
                HASH_SIZE * 2
            ));
        }
        for chunk in data.chunks(HASH_SIZE * 2) {
            let mut left = [0; HASH_SIZE];
            let mut right = [0; HASH_SIZE];
            left.copy_from_slice(&chunk[0..HASH_SIZE]);
            right.copy_from_slice(&data[HASH_SIZE..HASH_SIZE * 2]);
            let node = Node { left, right };
            self.branches.insert(node.hash(), node);
        }
        Ok(true)
    }

    // pub fn add_serialized_transactions(
    //     &mut self,
    //     data: &[u8],
    //     users: &mut HashMap<secp256k1::PublicKey, crate::user::User>,
    // ) -> Result<Vec<Transaction>, String> {
    //     let mut transactions = Vec::new();
    //     let mut i = 0;
    //     while i < data.len() {
    //         let pre_i = i;
    //         let mut hash = [0; 32];
    //         hash.copy_from_slice(Sha256::digest(&data[pre_i..i]).as_slice());
    //         self.leafs
    //             .insert(hash, *Transaction::from_serialized(&data, &mut i, users)?);
    //         transactions.push(*Transaction::from_serialized(&data, &mut i, users)?);
    //     }
    //     Ok(transactions)
    // }

    pub fn serialize_all_transactions(&self) -> Result<Vec<u8>, String> {
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

    pub fn serialize_all_nodes(&self) -> Result<Vec<u8>, String> {
        let mut serialized = vec![0; self.branches.len() * HASH_SIZE * 2];
        let i = 0;
        for node in self.branches.iter() {
            serialized[i..HASH_SIZE].copy_from_slice(&node.1.serialize());
        }
        Ok(serialized)
    }

    pub fn create_tree_from_leafs(&mut self) -> Result<[u8; 32], String> {
        if !self.branches.is_empty() {
            return Err(String::from("Tree already has branches"));
        }
        let mut branch_queue = self.leafs.keys().cloned().collect::<Vec<[u8; 32]>>();

        while branch_queue.len() > 1 {
            let mut tmp_branch_queue = Vec::new();
            for leaf_pair in branch_queue.chunks(2) {
                let node;
                if leaf_pair.len() == 2 {
                    node = Node::new(leaf_pair[0], leaf_pair[1]);
                    tmp_branch_queue.push(node.hash());
                    self.add_node(node)?;
                } else {
                    tmp_branch_queue.push(leaf_pair[0]);
                }
            }
            branch_queue = tmp_branch_queue;
        }
        Ok(branch_queue[0])
    }

    pub fn get_transactions(
        &self,
        hashes: Vec<[u8; 32]>,
    ) -> Result<Vec<&Transaction>, (Vec<&Transaction>, Vec<[u8; 32]>)> {
        let mut missing = Vec::new();
        let mut found = Vec::new();
        for hash in hashes {
            match self.leafs.get(&hash) {
                Some(leaf) => found.push(leaf),
                None => missing.push(hash),
            }
        }
        if !missing.is_empty() {
            Err((found, missing))
        } else {
            Ok(found)
        }
    }

    pub fn is_ancestor(
        &self,
        descendant: &Transaction,
        ancestor: [u8; 32],
    ) -> Result<&Transaction, Vec<[u8; 32]>> {
        let current_hash = ancestor;
        let tmp_node = self.branches.get(&current_hash);
        match tmp_node {
            Some(node) => {
                let mut errs;
                match self.is_ancestor(descendant, node.left) {
                    Ok(left) => return Ok(left),
                    Err(e) => errs = e,
                };
                match self.is_ancestor(descendant, node.right) {
                    Ok(right) => return Ok(right),
                    Err(mut e) => errs.append(&mut e),
                };
                Err(errs)
            }
            None => match self.leafs.get(&current_hash) {
                Some(result) => Ok(result),
                None => Err(vec![current_hash]),
            },
        }
    }

    pub fn add_leaf(&mut self, leaf: Transaction) -> Result<bool, String> {
        match self.leafs.get(&leaf.hash()?) {
            Some(_) => Err(String::from("Leaf already exists")),
            None => match self.leafs.insert(leaf.hash()?, leaf) {
                Some(_) => Err(String::from("Could not insert leaf")),
                None => Ok(true),
            },
        }
    }

    pub fn add_node(&mut self, node: Node) -> Result<bool, String> {
        match self.branches.get(&node.hash()) {
            Some(_) => Err(String::from("Node already exists")),
            None => match self.branches.insert(node.hash(), node) {
                Some(_) => Err(String::from("Could not insert node")),
                None => Ok(true),
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

    pub fn is_complete(&self, root: [u8; HASH_SIZE]) -> Result<usize, String> {
        let found_node = self.branches.get(&root);
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
            (None, Some(_)) => Ok(0),
            _ => Err(format!("Missing node with hash  {:?}", root)),
        }
    }
}
