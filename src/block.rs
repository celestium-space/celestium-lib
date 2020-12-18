use crate::{
    serialize::Serialize, transaction::TransactionBlock, universal_id::UniversalId, user::User,
};
use secp256k1::PublicKey;
use std::{collections::HashMap, fmt};

pub struct BlockHash {
    value: u32,
}

impl BlockHash {
    pub fn new(value: u32) -> BlockHash {
        BlockHash { value: value }
    }

    pub fn from_hash(data: Vec<u8>) -> BlockHash {
        BlockHash {
            value: ((data[0] as u32) << 24)
                + ((data[1] as u32) << 16)
                + ((data[2] as u32) << 8)
                + (data[3] as u32),
        }
    }

    pub fn contains_enough_work(&self) -> bool {
        true
    }

    pub fn is_zero_block(&self) -> bool {
        self.value == 0
    }
}

impl PartialEq for BlockHash {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:x}", self.value)
    }
}

impl Serialize for BlockHash {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        _: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<BlockHash>, String> {
        let block_hash = BlockHash {
            value: ((data[*i] as u32) << 24)
                + ((data[*i + 1] as u32) << 16)
                + ((data[*i + 2] as u32) << 8)
                + (data[*i + 3] as u32),
        };
        *i += block_hash.serialized_len()?;
        Ok(Box::new(block_hash))
    }

    fn serialize_into(&mut self, buffer: &mut [u8], i: &mut usize) -> Result<usize, String> {
        buffer[*i + 0] = (self.value >> 24) as u8;
        buffer[*i + 1] = (self.value >> 16) as u8;
        buffer[*i + 2] = (self.value >> 8) as u8;
        buffer[*i + 3] = self.value as u8;
        *i += self.serialized_len()?;
        return Ok(self.serialized_len()?);
    }

    fn serialized_len(&self) -> Result<usize, String> {
        return Ok(4);
    }
}

pub struct Block {
    transaction_blocks: Vec<TransactionBlock>,
    uid: UniversalId,
    pub back_hash: BlockHash,
    pub finder: PublicKey,
    pub magic: Vec<u8>,
}

impl Block {
    pub fn new(
        transactions: Vec<TransactionBlock>,
        uid: UniversalId,
        back_hash: BlockHash,
        finder: PublicKey,
        magic: Vec<u8>,
    ) -> Block {
        Block {
            transaction_blocks: transactions,
            uid,
            back_hash,
            finder,
            magic,
        }
    }

    pub fn get_user_value_change(&mut self, pk: &mut PublicKey) -> Result<i32, String> {
        let mut tmp_value = 0;
        for transaction_block in self.transaction_blocks.iter_mut() {
            tmp_value += transaction_block.get_user_value_change(pk)?;
        }
        return Ok(tmp_value);
    }
}

impl Serialize for Block {
    fn from_serialized(
        data: &[u8],
        mut i: &mut usize,
        users: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<Block>, String> {
        let mut transaction_blocks = Vec::new();
        let mut uid;
        loop {
            let mut j = *i;
            uid = *UniversalId::from_serialized(&data, &mut j, users)?;
            if !uid.is_magic() {
                let transaction = *TransactionBlock::from_serialized(&data, &mut i, users)?;
                transaction_blocks.push(transaction);
            } else {
                break;
            }
        }
        *i += uid.serialized_len()?;
        let back_hash = *BlockHash::from_serialized(&data, &mut i, users)?;
        if transaction_blocks.len() > 0 && back_hash.is_zero_block() {
            let zero_block_owner = transaction_blocks[0].transactions[0].to_pk;
            for transaction_block in transaction_blocks.iter() {
                for transaction in transaction_block.transactions.iter() {
                    if transaction.to_pk == zero_block_owner {
                        users
                            .entry(zero_block_owner)
                            .or_insert(User::new(zero_block_owner))
                            .give(transaction.value)?;
                    }
                }
            }
        }
        let finder = *PublicKey::from_serialized(&data, &mut i, users)?;
        let magic_len = uid.get_value();
        let magic = data[*i..*i + magic_len as usize].to_vec();
        *i += magic_len as usize;
        return Ok(Box::new(Block::new(
            transaction_blocks,
            uid,
            back_hash,
            finder,
            magic,
        )));
    }

    fn serialize_into(&mut self, data: &mut [u8], i: &mut usize) -> Result<usize, String> {
        let start_i = *i;
        for transaction_block in self.transaction_blocks.iter_mut() {
            transaction_block.serialize_into(data, i)?;
        }
        let uid = &mut UniversalId::new(false, true, self.magic.len() as u16);
        uid.serialize_into(data, i)?;
        self.back_hash.serialize_into(data, i)?;
        self.finder.serialize_into(data, i)?;
        for j in 0..uid.get_value() as usize {
            data[*i + j] = self.magic[j];
        }
        *i += uid.get_value() as usize;
        return Ok(*i - start_i);
    }

    fn serialized_len(&self) -> Result<usize, String> {
        let mut tmp_len = 0usize;
        for transaction_block in &self.transaction_blocks {
            tmp_len += transaction_block.serialized_len()?;
        }
        let len = tmp_len
            + self.uid.serialized_len()?
            + 1
            + 4
            + self.finder.serialized_len()?
            + self.magic.len();
        return Ok(len);
    }
}
