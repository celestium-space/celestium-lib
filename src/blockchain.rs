use crate::{
    block::Block,
    block_hash::BlockHash,
    serialize::{DynamicSized, Serialize},
    wallet::HASH_SIZE,
};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

pub struct Blockchain {
    pub blocks: HashMap<BlockHash, Block>,
    head: Option<BlockHash>,
}

impl Blockchain {
    pub fn new(blocks: Vec<Block>) -> Blockchain {
        let head = blocks.last().map(|h| h.hash());
        Blockchain {
            blocks: blocks
                .iter()
                .map(|x| (x.hash(), x.clone()))
                .collect::<HashMap<BlockHash, Block>>(),
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
                hash = Sha3_256::digest(&data[*i - block_len..*i]).to_vec();
                if !BlockHash::contains_enough_work(&hash) {
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

    pub fn get_head_hash(&self) -> BlockHash {
        self.head.as_ref().unwrap_or(&BlockHash::default()).clone()
    }

    pub fn add_block(&mut self, block: Block) -> Result<[u8; HASH_SIZE], String> {
        if self.head.is_some() && block.back_hash != *self.head.as_ref().unwrap() {
            Err(format!(
                "New block not pointing at old head, expected backhash {} got {}",
                self.head.as_ref().unwrap(),
                block.back_hash
            ))
        } else {
            let hash = block.hash();
            let transactions_hash = block.transactions_hash.hash();
            self.blocks.insert(hash.clone(), block);
            self.head = Some(hash);
            Ok(transactions_hash)
        }
    }

    pub fn add_serialized_block(&mut self, block: Vec<u8>) -> Result<[u8; HASH_SIZE], String> {
        let block = *Block::from_serialized(&block, &mut 0)?;
        self.add_block(block)
    }

    pub fn contains_block(&self, hash: BlockHash) -> bool {
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
        match &self.head {
            Some(head) => {
                let mut hash = head;
                let mut blocks = Vec::new();
                for j in 0..n {
                    match self.blocks.get(&hash) {
                        Some(b) => {
                            blocks.insert(0, b);
                            hash = &b.back_hash;
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
                    merkle_roots.push(block.transactions_hash.hash());
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
