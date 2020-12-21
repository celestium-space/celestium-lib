use crate::{
    magic::Magic, serialize::Serialize, transaction::TransactionBlock, universal_id::UniversalId,
    user::User,
};
use secp256k1::PublicKey;
use std::{collections::HashMap, fmt};

pub struct BlockHash {
    value: [u8; 32],
}

impl BlockHash {
    pub fn new_unworked() -> BlockHash {
        BlockHash { value: [0xff; 32] }
    }

    pub fn contains_enough_work(&self) -> bool {
        if self.value[0] == 0 && self.value[1] == 0 && self.value[2] == 0 {
            //&& self.value[3] == 0 {
            return true;
        }
        false
    }

    pub fn is_zero_block(&self) -> bool {
        self.value == [0; 32]
    }
}

impl Default for BlockHash {
    fn default() -> Self {
        BlockHash { value: [0; 32] }
    }
}

impl PartialEq for BlockHash {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x?}", self.value)
    }
}

impl Serialize for BlockHash {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        _: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<BlockHash>, String> {
        if data.len() - *i < 32 {
            return Err(format!(
                "Cannot deserialize hash, expected buffer with least 32 bytes left got {}",
                data.len() + *i
            ));
        };
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[*i..*i + 32]);
        *i += 32;
        Ok(Box::new(BlockHash { value: hash }))
    }

    fn serialize_into(&self, buffer: &mut [u8], i: &mut usize) -> Result<usize, String> {
        buffer[*i..*i + 32].copy_from_slice(&self.value);
        *i += self.serialized_len()?;
        Ok(self.serialized_len()?)
    }

    fn serialized_len(&self) -> Result<usize, String> {
        Ok(32)
    }
}

pub struct Block {
    transaction_blocks: Vec<TransactionBlock>,
    uid: UniversalId,
    pub back_hash: BlockHash,
    pub block_hash: BlockHash,
    pub finder: PublicKey,
    pub magic: Magic,
}

impl Block {
    pub fn new(
        transactions: Vec<TransactionBlock>,
        uid: UniversalId,
        back_hash: BlockHash,
        finder: PublicKey,
        magic: Magic,
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
        Ok(tmp_value)
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
        if !transaction_blocks.is_empty() && back_hash.is_zero_block() {
            let zero_block_owner = transaction_blocks[0].transactions[0].to_pk;
            for transaction_block in transaction_blocks.iter() {
                for transaction in transaction_block.transactions.iter() {
                    if transaction.to_pk == zero_block_owner {
                        users
                            .entry(zero_block_owner)
                            .or_insert_with(|| User::new(zero_block_owner))
                            .give(transaction.value)?;
                    }
                }
            }
        }
        let finder = *PublicKey::from_serialized(&data, &mut i, users)?;
        let magic = *Magic::from_serialized(&data, &mut i, users)?;
        Ok(Box::new(Block::new(
            transaction_blocks,
            uid,
            back_hash,
            finder,
            magic,
        )))
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<usize, String> {
        let start_i = *i;
        for transaction_block in self.transaction_blocks.iter() {
            transaction_block.serialize_into(data, i)?;
        }
        let uid = &mut UniversalId::new(false, true, self.magic.serialized_len()? as u16);
        uid.serialize_into(data, i)?;
        self.back_hash.serialize_into(data, i)?;
        self.finder.serialize_into(data, i)?;
        self.magic.serialize_into(data, i)?;
        Ok(*i - start_i)
    }

    fn serialized_len(&self) -> Result<usize, String> {
        let mut tmp_len = 0usize;
        for transaction_block in &self.transaction_blocks {
            tmp_len += transaction_block.serialized_len()?;
        }
        let len = tmp_len
            + self.uid.serialized_len()?
            + self.back_hash.serialized_len()?
            + self.finder.serialized_len()?
            + self.magic.serialized_len()?;
        Ok(len)
    }
}
