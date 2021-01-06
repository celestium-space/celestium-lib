use crate::{
    block::{Block, BlockTime},
    block_hash::BlockHash,
    block_version::BlockVersion,
    magic::Magic,
    serialize::{DynamicSized, Serialize, StaticSized},
    user::User,
};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub struct Blockchain {
    blocks: Vec<Block>,
}

impl Blockchain {
    pub fn new(blocks: Vec<Block>) -> Blockchain {
        Blockchain { blocks }
    }

    fn parse_blocks(
        data: &[u8],
        mut i: &mut usize,
        users: &mut HashMap<PublicKey, User>,
    ) -> Result<Vec<Block>, String> {
        let mut hash = BlockHash::default();
        let mut tmp_blocks = Vec::new();
        while *i < data.len() {
            let block = *Block::from_serialized(&data, &mut i, users)?;
            if block.back_hash == hash {
                let block_len = Block::serialized_len();
                hash = *BlockHash::from_serialized(
                    Sha256::digest(&data[*i - block_len..*i]).as_slice(),
                    &mut 0,
                    users,
                )?;
                let valid_hash = hash.contains_enough_work();
                if !valid_hash {
                    return Err(format!(
                        "Block with len {} at byte {} with magic {}, hashes to {}, which does not represent enough work",
                        block_len, *i - block_len, block.magic, hash
                    ));
                }
                tmp_blocks.push(block);
            } else {
                return Err(format!(
                    "Block at addr {} in chain has wrong back hash. Expected {} got {}",
                    i, hash, block.back_hash
                ));
            }
        }
        Ok(tmp_blocks)
    }
    pub fn get_block_time(&self, hash: [u8; 32]) -> Result<BlockTime, String> {
        for block in self.blocks.iter() {
            if block.hash() == hash {
                return Ok(block.time.clone());
            }
        }
        Err(format!(
            "Block with hash {:?} not found in blockchain",
            hash
        ))
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn create_unmined_block(
        &self,
        merkle_root: BlockHash,
        secs_since_epoc: u32,
    ) -> Result<Vec<u8>, String> {
        let back_hash;
        if !self.blocks.is_empty() {
            let mut last_block_serialized = vec![0; Block::serialized_len()];
            let mut i = 0;
            self.blocks
                .last()
                .unwrap()
                .serialize_into(&mut last_block_serialized, &mut i)?;
            back_hash = *BlockHash::from_serialized(
                &Sha256::digest(&last_block_serialized[..i]),
                &mut 0,
                &mut HashMap::new(),
            )?;
        } else {
            back_hash = BlockHash::default();
        }
        let unmined_block = Block::new(
            BlockVersion::default(),
            merkle_root,
            back_hash,
            BlockTime::new(secs_since_epoc),
            Magic::new(0),
        );
        let mut unmined_serialized_block = vec![0u8; Block::serialized_len()];
        unmined_block.serialize_into(&mut unmined_serialized_block, &mut 0)?;
        Ok(unmined_serialized_block)
    }

    pub fn get_head_hash(&self) -> Result<[u8; 32], String> {
        match self.blocks.last() {
            Some(b) => Ok(b.hash()),
            None => Err(String::from("Cannot get head from empty blockchain")),
        }
    }

    pub fn add_block(&mut self, block: Block) -> Result<usize, String> {
        self.blocks.push(block);
        Ok(self.blocks.len())
    }

    pub fn add_serialized_block(
        &mut self,
        block: Vec<u8>,
        users: &mut HashMap<PublicKey, User>,
    ) -> Result<Vec<u8>, String> {
        let block = *Block::from_serialized(&block, &mut 0, users)?;
        self.blocks.push(block);
        let mut buffer = vec![0u8; self.serialized_len()];
        self.serialize_into(&mut buffer, &mut 0)?;
        Ok(buffer)
    }
}

impl Serialize for Blockchain {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        users: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<Blockchain>, String> {
        let blocks = Blockchain::parse_blocks(data, i, users)?;
        Ok(Box::new(Blockchain::new(blocks)))
    }

    fn serialize_into(&self, data: &mut [u8], mut i: &mut usize) -> Result<usize, String> {
        let mut hash = BlockHash::default();
        let orig_i = *i;
        for block in self.blocks.iter() {
            if block.back_hash != hash {
                return Err(format!(
                    "Block at index {} in chain has wrong back hash. Expected {} got {}",
                    i, hash, block.back_hash
                ));
            }
            let pre_i = *i;
            block.serialize_into(data, &mut i)?;
            hash = *BlockHash::from_serialized(
                &Sha256::digest(&data[pre_i..*i]),
                &mut 0,
                &mut HashMap::new(),
            )?;
        }
        Ok(*i - orig_i)
    }
}

impl DynamicSized for Blockchain {
    fn serialized_len(&self) -> usize {
        self.blocks.len() * Block::serialized_len()
    }
}
