use crate::{
    block::Block,
    block_hash::BlockHash,
    block_version::BlockVersion,
    merkle_forest::HASH_SIZE,
    serialize::{DynamicSized, Serialize},
    transaction_varuint::TransactionVarUint,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub struct Blockchain {
    pub blocks: HashMap<[u8; HASH_SIZE], Block>,
    head: Option<[u8; HASH_SIZE]>,
}

impl Blockchain {
    pub fn new(blocks: Vec<Block>) -> Blockchain {
        let head = match blocks.last() {
            Some(h) => Some(h.hash()),
            None => None,
        };
        Blockchain {
            blocks: blocks
                .iter()
                .map(|x| (x.hash(), x.clone()))
                .collect::<HashMap<[u8; HASH_SIZE], Block>>(),
            head,
        }
    }

    fn parse_blocks(data: &[u8], mut i: &mut usize) -> Result<Vec<Block>, String> {
        let mut hash = BlockHash::default().hash().to_vec();
        let mut tmp_blocks = Vec::new();
        while *i < data.len() {
            let block = *Block::from_serialized(&data, &mut i)?;
            if block.back_hash.hash().to_vec() == hash {
                let block_len = block.serialized_len();
                hash = Sha256::digest(&data[*i - block_len..*i]).to_vec();
                if BlockHash::contains_enough_work(&hash) {
                    return Err(format!(
                        "Blockchain - Block with len {} at byte {} with magic {}, hashes to {:x?}, which does not represent enough work",
                        block_len, *i - block_len, block.magic, hash
                    ));
                }
                tmp_blocks.push(block);
            } else {
                return Err(format!(
                    "Block at addr {} in chain has wrong back hash. Expected {:x?} got {}",
                    i, hash, block.back_hash
                ));
            }
        }
        Ok(tmp_blocks)
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn create_unmined_block(&self, merkle_root: BlockHash) -> Result<Vec<u8>, String> {
        let back_hash;
        match self.head {
            Some(head) => match self.blocks.get(&head) {
                Some(last_block) => {
                    let mut last_block_serialized = vec![0; last_block.serialized_len()];
                    let mut i = 0;
                    self.blocks
                        .get(&self.head.unwrap())
                        .unwrap()
                        .serialize_into(&mut last_block_serialized, &mut i)?;
                    back_hash = *BlockHash::from_serialized(
                        &Sha256::digest(&last_block_serialized[..i]),
                        &mut 0,
                    )?;
                }
                None => back_hash = BlockHash::default(),
            },
            None => back_hash = BlockHash::default(),
        }
        let unmined_block = Block::new(
            BlockVersion::default(),
            merkle_root,
            back_hash,
            TransactionVarUint::from(0),
        );
        let mut unmined_serialized_block = vec![0u8; unmined_block.serialized_len()];
        unmined_block.serialize_into(&mut unmined_serialized_block, &mut 0)?;
        Ok(unmined_serialized_block)
    }

    pub fn get_head_hash(&self) -> [u8; 32] {
        match self.head {
            Some(h) => h,
            None => [0u8; 32],
        }
    }

    pub fn add_block(&mut self, block: Block) -> Result<[u8; HASH_SIZE], String> {
        if self.head.is_some() && block.back_hash.hash() != self.head.unwrap() {
            Err(format!(
                "New block not pointing at old head, expected backhash {:?} got {:?}",
                self.head.unwrap(),
                block.back_hash.hash()
            ))
        } else {
            let hash = block.hash();
            let merkle_root = block.merkle_root.hash();
            self.blocks.insert(hash, block);
            self.head = Some(hash);
            Ok(merkle_root)
        }
    }

    pub fn add_serialized_block(&mut self, block: Vec<u8>) -> Result<[u8; HASH_SIZE], String> {
        let block = *Block::from_serialized(&block, &mut 0)?;
        self.add_block(block)
    }

    pub fn contains_block(&self, hash: [u8; 32]) -> bool {
        self.blocks.contains_key(&hash)
    }

    pub fn serialize_n_blocks(
        &self,
        data: &mut [u8],
        mut i: &mut usize,
        n: usize,
    ) -> Result<Vec<[u8; HASH_SIZE]>, String> {
        if n > self.blocks.len() {
            return Err(format!(
                "Trying to serialize more blocks than blockchain len, expected max {} got {}",
                self.blocks.len(),
                n
            ));
        }
        let mut merkle_roots = Vec::new();
        match self.head {
            Some(head) => {
                let mut hash = head;
                let mut blocks = Vec::new();
                for j in 0..n {
                    match self.blocks.get(&hash) {
                        Some(b) => {
                            blocks.insert(0, b);
                            hash = b.back_hash.hash();
                        }
                        None => {
                            return Err(format!(
                                "Reached end of blockchain before time, expected {} got {}",
                                n, j
                            ))
                        }
                    }
                }
                for block in blocks {
                    merkle_roots.push(block.merkle_root.hash());
                    block.serialize_into(data, &mut i)?;
                }
            }
            None => return Err(String::from("Cannot serialize empty blockchain")),
        };
        Ok(merkle_roots)
    }
}

impl Serialize for Blockchain {
    fn from_serialized(data: &[u8], i: &mut usize) -> Result<Box<Blockchain>, String> {
        let blocks = Blockchain::parse_blocks(data, i)?;
        Ok(Box::new(Blockchain::new(blocks)))
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<(), String> {
        self.serialize_n_blocks(data, i, self.blocks.len())?;
        Ok(())
    }
}

impl DynamicSized for Blockchain {
    fn serialized_len(&self) -> usize {
        let mut len = 0;
        for (_, block) in self.blocks.iter() {
            len += block.serialized_len();
        }
        len
    }
}
