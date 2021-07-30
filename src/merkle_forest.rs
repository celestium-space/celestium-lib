use crate::{
    serialize::{DynamicSized, Serialize},
    transaction::Transaction,
};
use sha3::{Digest, Sha3_256};
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

    pub fn hash(&self) -> [u8; HASH_SIZE] {
        let mut hash = [0; HASH_SIZE];
        let mut serialized = [0; HASH_SIZE * 2];
        self.serialize_into(&mut serialized, &mut 0).unwrap();
        hash.copy_from_slice(Sha3_256::digest(&serialized).as_slice());
        hash
    }
}

impl Serialize for Node {
    fn from_serialized(data: &[u8], i: &mut usize) -> Result<Box<Self>, String> {
        let mut left = [0u8; HASH_SIZE];
        left.copy_from_slice(&data[*i..*i + HASH_SIZE]);
        *i += HASH_SIZE;
        let mut right = [0u8; HASH_SIZE];
        right.copy_from_slice(&data[*i..HASH_SIZE]);
        *i += HASH_SIZE;
        Ok(Box::new(Node { left, right }))
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<(), String> {
        data[*i..*i + HASH_SIZE].copy_from_slice(&self.left);
        *i += HASH_SIZE;
        data[*i..*i + HASH_SIZE].copy_from_slice(&self.right);
        *i += HASH_SIZE;
        Ok(())
    }
}

#[derive(Clone)]
pub struct MerkleForest<T> {
    leafs: HashMap<[u8; HASH_SIZE], T>,
    pub branches: HashMap<[u8; HASH_SIZE], Node>,
}

impl MerkleForest<Transaction> {
    pub fn new_empty() -> Self {
        MerkleForest {
            leafs: HashMap::new(),
            branches: HashMap::new(),
        }
    }

    pub fn new_complete_from_leafs(leafs: Vec<Transaction>) -> Result<(Self, [u8; 32]), String> {
        if leafs.len() > 256 {
            return Err("Blockchain can only contain 256 leafs".to_string());
        } else if leafs.len() == 1 {
            return Ok((
                MerkleForest {
                    leafs: leafs
                        .iter()
                        .map(|x| (x.hash(), x.clone()))
                        .collect::<HashMap<[u8; HASH_SIZE], Transaction>>(),
                    branches: HashMap::default(),
                },
                leafs[0].hash(),
            ));
        }

        let mut branches = HashMap::new();
        let mut branch_queue = leafs
            .iter()
            .map(|x| x.hash())
            .collect::<Vec<[u8; HASH_SIZE]>>();
        let mut root = None;
        while branch_queue.len() > 1 {
            let mut tmp_branch_queue = Vec::new();
            for leaf_pair in branch_queue.chunks(2) {
                if leaf_pair.len() == 2 {
                    let node = Node::new(leaf_pair[0], leaf_pair[1]);
                    let node_hash = node.hash();
                    root = Some(node.clone());
                    if branches.insert(node.hash(), node).is_some() {
                        return Err(String::from("Could not insert node"));
                    };
                    tmp_branch_queue.push(node_hash);
                } else {
                    tmp_branch_queue.push(leaf_pair[0]);
                }
            }
            branch_queue = tmp_branch_queue;
        }
        match root {
            Some(r) => Ok((
                MerkleForest {
                    leafs: leafs
                        .iter()
                        .map(|x| (x.hash(), x.clone()))
                        .collect::<HashMap<[u8; HASH_SIZE], Transaction>>(),
                    branches,
                },
                r.hash(),
            )),
            None => Err(String::from("Could not create root")),
        }
    }

    pub fn new_complete_from_serialized_leafs(
        serialized_leafs: Vec<u8>,
    ) -> Result<(Self, [u8; HASH_SIZE]), String> {
        let mut i = 0;
        let mut leafs = Vec::new();
        while i < serialized_leafs.len() {
            leafs.push(*Transaction::from_serialized(&serialized_leafs, &mut i)?);
        }

        MerkleForest::new_complete_from_leafs(leafs)
    }

    pub fn leaf_len(&self) -> usize {
        self.leafs.len()
    }

    pub fn add_transactions(&mut self, data: Vec<Transaction>) -> Result<(), String> {
        for transaction in data {
            if let Some(l) = self.leafs.insert(transaction.hash(), transaction) {
                let leaf_hash = l.hash();
                self.leafs.insert(leaf_hash, l);
                return Err(format!(
                    "Transaction with hash {:?} already exists in merkle forest",
                    leaf_hash
                ));
            }
        }
        Ok(())
    }

    pub fn add_branches(&mut self, branches: Vec<Node>) -> Result<(), String> {
        for node in branches {
            if let Some(b) = self.branches.insert(node.hash(), node) {
                let branch_hash = b.hash();
                self.branches.insert(branch_hash, b);
                return Err(format!(
                    "Branch with hash {:?} already exists in merkle forest",
                    branch_hash
                ));
            }
        }
        Ok(())
    }

    pub fn add_serialized_transactions(
        &mut self,
        data: &[u8],
        i: &mut usize,
    ) -> Result<bool, String> {
        while *i < data.len() {
            let transaction = *Transaction::from_serialized(&data, i)?;
            self.leafs.insert(transaction.hash(), transaction);
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
        let mut i = 0;
        for (_, node) in self.branches.iter() {
            node.serialize_into(&mut serialized, &mut i)?;
        }
        Ok(serialized)
    }

    #[allow(clippy::type_complexity)]
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
        match self.leafs.get(&leaf.hash()) {
            Some(_) => Err(String::from("Leaf already exists")),
            None => match self.leafs.insert(leaf.hash(), leaf) {
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

    pub fn add_merkle_tree(
        &mut self,
        merkle_tree: MerkleForest<Transaction>,
    ) -> Result<(), String> {
        self.leafs.extend(merkle_tree.leafs);
        self.branches.extend(merkle_tree.branches);
        Ok(())
    }

    pub fn get_merkle_tree(&self, root: [u8; 32]) -> Result<(Vec<Node>, Vec<Transaction>), String> {
        match self.branches.get(&root) {
            Some(node) => {
                let (n1, t1) = self.get_merkle_tree(node.right)?;
                let (n2, t2) = self.get_merkle_tree(node.left)?;
                Ok((
                    [[node.clone()].to_vec(), n1, n2].concat(),
                    [t1, t2].concat(),
                ))
            }
            None => match self.leafs.get(&root) {
                Some(leaf) => Ok((Vec::new(), vec![leaf.clone()])),
                None => Err(format!(
                    "Root not found in merkle tree {:?}; {:?}",
                    self.branches.values().next().unwrap().hash(),
                    root
                )),
            },
        }
    }

    pub fn get_merkle_forest(
        &mut self,
        roots: Vec<[u8; 32]>,
    ) -> Result<(Vec<Node>, Vec<Transaction>), String> {
        let mut nodes = Vec::new();
        let mut transactions = Vec::new();
        for root in roots {
            let (mut root_nodes, mut root_transactions) = self.get_merkle_tree(root)?;
            nodes.append(&mut root_nodes);
            transactions.append(&mut root_transactions);
        }
        Ok((nodes, transactions))
    }

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
            _ => Err(format!("Missing node with hash {:?}", root)),
        }
    }
}
