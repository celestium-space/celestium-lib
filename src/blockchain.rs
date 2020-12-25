use crate::{
    block::Block,
    block_hash::BlockHash,
    magic::Magic,
    serialize::{DynamicSized, Serialize, StaticSized},
    transaction::TransactionBlock,
    transaction_value::TransactionValue,
    universal_id::UniversalId,
    user::User,
};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const BLOCK_ZERO_FEE: u64 = u64::MAX;

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

    pub fn create_unmined_block(
        &self,
        transaction_blocks: &[TransactionBlock],
        finder_pk: PublicKey,
    ) -> Result<Vec<u8>, String> {
        let mut transaction_blocks_len = 0;
        for transaction_block in transaction_blocks.iter() {
            transaction_blocks_len += transaction_block.serialized_len();
        }
        let back_hash;
        if !self.blocks.is_empty() {
            let mut last_block_serialized = vec![0; Block::serialized_len()];
            let mut i = 0;
            self.blocks
                .last()
                .unwrap()
                .serialize_into(&mut last_block_serialized, &mut i)?;
            back_hash = BlockHash::from_serialized(
                &Sha256::digest(&last_block_serialized[..i]),
                &mut 0,
                &mut HashMap::new(),
            )?;
        } else {
            back_hash = Box::new(BlockHash::default());
        }
        let magic = Magic::new(0);
        let uid = UniversalId::new(false, Magic::serialized_len() as u16);
        let mut unmined_block = vec![
            0;
            transaction_blocks_len
                + UniversalId::serialized_len()
                + BlockHash::serialized_len()
                + PublicKey::serialized_len()
                + Magic::serialized_len()
        ];
        let mut i = 0;
        for transaction_block in transaction_blocks.iter() {
            transaction_block.serialize_into(&mut unmined_block, &mut i)?;
        }
        uid.serialize_into(&mut unmined_block, &mut i)?;
        back_hash.serialize_into(&mut unmined_block, &mut i)?;
        finder_pk.serialize_into(&mut unmined_block, &mut i)?;
        magic.serialize_into(&mut unmined_block, &mut i)?;
        Ok(unmined_block.to_vec())
    }

    pub fn add_serialized_block(
        &mut self,
        block: Vec<u8>,
        users: &mut HashMap<PublicKey, User>,
    ) -> Result<Vec<u8>, String> {
        let block = *Block::from_serialized(&block, &mut 0, &mut users)?;
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
        let block_zero_owner_pk = *PublicKey::from_serialized(&data[2..35], &mut 0, &mut users)?;
        let mut block_zero_owner = User::new(block_zero_owner_pk);
        block_zero_owner
            .give(TransactionValue::new_coin_transfer(BLOCK_ZERO_FEE, 0)?)
            .unwrap();
        if users
            .insert(block_zero_owner_pk, block_zero_owner)
            .is_some()
        {
            return Err("Unexpected: Block zero user already exists in system".to_string());
        }
        let mut i = 0;
        let blocks = Blockchain::parse_blocks(data, &mut i, &mut users)?;
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
        let mut tmp_len = 0usize;
        for block in &self.blocks {
            tmp_len += Block::serialized_len();
        }
        tmp_len
    }
}
