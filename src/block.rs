use crate::{
    block_hash::BlockHash, magic::Magic, serialize::Serialize, transaction::TransactionBlock,
    universal_id::UniversalId, user::User,
};
use merkle::MerkleTree;
use secp256k1::PublicKey;
use std::collections::HashMap;

pub struct Block {
    transaction_blocks: MerkleTree<TransactionBlock>,
    uid: UniversalId,
    pub back_hash: BlockHash,
    pub block_hash: BlockHash,
    pub finder: PublicKey,
    pub magic: Magic,
}

impl Block {
    pub fn new(
        transaction_blocks: MerkleTree<TransactionBlock>,
        uid: UniversalId,
        back_hash: BlockHash,
        block_hash: BlockHash,
        finder: PublicKey,
        magic: Magic,
    ) -> Block {
        Block {
            transaction_blocks,
            uid,
            back_hash,
            block_hash,
            finder,
            magic,
        }
    }

    // pub fn get_user_value_change(&mut self, pk: &mut PublicKey) -> Result<i32, String> {
    //     let mut tmp_value = 0;
    //     for transaction_block in self.transaction_blocks.iter_mut() {
    //         tmp_value += transaction_block.get_user_value_change(pk)?;
    //     }
    //     Ok(tmp_value)
    // }
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
        let t = MerkleTree::from_vec(&ring::digest::SHA256, transaction_blocks);
        let root_hash = t.root_hash();

        Ok(Box::new(Block::new(
            t,
            uid,
            back_hash,
            *BlockHash::from_serialized(&root_hash, &mut 0, &mut HashMap::new())?,
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
