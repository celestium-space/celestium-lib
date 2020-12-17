use crate::{
    block::{Block, BlockHash},
    serialize::Serialize,
    transaction::TransactionValue,
    user::User,
};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub struct Blockchain {
    blocks: Vec<Block>,
    users: HashMap<PublicKey, User>,
}

// fn get_block_finders_fee(_: usize) -> i32 {
//     return 1337;
// }

impl Blockchain {
    pub fn new(blocks: Vec<Block>, users: HashMap<PublicKey, User>) -> Blockchain {
        Blockchain {
            blocks: blocks,
            users: users,
        }
    }

    pub fn get_user_value_change(&mut self, pk: &mut PublicKey) -> Result<u32, String> {
        match self.users.get(pk) {
            Some(user) => Ok(user.get_balance()),
            None => Err(format!("No user with public key {}", pk)),
        }
    }

    pub fn get_users(self) -> Result<HashMap<PublicKey, User>, String> {
        return Ok(self.users);
    }

    pub fn from_binary(
        data: &[u8],
        block_zero_owner_pk: PublicKey,
    ) -> Result<Box<Blockchain>, String> {
        let mut block_zero_owner = User::new(block_zero_owner_pk);
        block_zero_owner
            .give(TransactionValue::new(100000, Some(0)))
            .unwrap();
        let mut users = HashMap::new();
        users.insert(block_zero_owner_pk, block_zero_owner);
        let mut i = 0;
        let blocks = Blockchain::parse_blocks(data, &mut i, &mut users)?;
        let user = users.get_mut(&block_zero_owner_pk).unwrap();
        user.take(TransactionValue::new(100000, Some(0))).unwrap();
        Ok(Box::new(Blockchain::new(blocks, users)))
    }

    fn parse_blocks(
        data: &[u8],
        mut i: &mut usize,
        users: &mut HashMap<PublicKey, User>,
    ) -> Result<Vec<Block>, String> {
        let mut hash = BlockHash::new(0);
        let mut tmp_blocks = Vec::new();
        while *i < data.len() {
            let block = *Block::from_serialized(&data, &mut i, users)?;
            if block.back_hash == hash {
                let block_len = block.serialized_len()?;
                let mut j = 0;
                hash = *BlockHash::from_serialized(
                    Sha256::digest(&data[*i - (block_len - 1)..*i]).as_slice(),
                    &mut j,
                    users,
                )?;
                let valid_hash = hash.contains_enough_work();
                if !valid_hash {
                    return Err(format!(
                        "Block {} with magic {:x?} does not represent enough work",
                        i, block.magic
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
        return Ok(tmp_blocks);
    }
}

impl Serialize for Blockchain {
    fn from_serialized(
        _: &[u8],
        _: &mut usize,
        _: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<Blockchain>, String> {
        todo!();
    }

    fn serialize_into(&mut self, data: &mut [u8], mut i: &mut usize) -> Result<usize, String> {
        let mut hash = BlockHash::new(0);
        let orig_i = *i;
        for block in self.blocks.iter_mut() {
            if block.back_hash != hash {
                return Err(format!(
                    "Block at index {} in chain has wrong back hash. Expected {} got {}",
                    i, hash, block.back_hash
                ));
            }
            let pre_i = *i;
            block.serialize_into(data, &mut i)?;
            let mut j = 0;
            hash = *BlockHash::from_serialized(
                &Sha256::digest(&data[pre_i..*i]),
                &mut j,
                &mut HashMap::new(),
            )?;
        }
        return Ok(*i - orig_i);
    }

    fn serialized_len(&self) -> Result<usize, String> {
        let mut tmp_len = 0usize;
        for block in &self.blocks {
            tmp_len += block.serialized_len()?;
        }
        return Ok(tmp_len);
    }
}
