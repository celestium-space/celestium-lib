use crate::{
    block_hash::BlockHash,
    block_version::BlockVersion,
    magic::Magic,
    merkle_forest,
    serialize::{Serialize, StaticSized},
    user::User,
};
use secp256k1::PublicKey;
use std::collections::HashMap;

const BLOCK_TIME_SIZE: usize = 4;

pub struct BlockTime {
    value: [u8; BLOCK_TIME_SIZE],
}

impl Serialize for BlockTime {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        _: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<Self>, String> {
        let bytes_left = data.len() - *i;
        if bytes_left < Self::serialized_len() {
            return Err(format!(
                "Too few bytes left to make block time, expected at least {} got {}",
                Self::serialized_len(),
                bytes_left
            ));
        }
        let mut value = [0; BLOCK_TIME_SIZE];
        value.copy_from_slice(&data[*i..Self::serialized_len()]);
        Ok(Box::new(BlockTime { value }))
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<usize, String> {
        let bytes_left = data.len() - *i;
        if bytes_left < Self::serialized_len() {
            return Err(format!(
                "Too few bytes left to serialize block time, expected at least {} got {}",
                Self::serialized_len(),
                bytes_left
            ));
        }
        data[*i..*i + Self::serialized_len()].copy_from_slice(&self.value);
        *i += Self::serialized_len();
        Ok(Self::serialized_len())
    }
}

impl StaticSized for BlockTime {
    fn serialized_len() -> usize {
        BLOCK_TIME_SIZE
    }
}

pub struct Block {
    pub version: BlockVersion,
    pub merkle_root: BlockHash,
    pub back_hash: BlockHash,
    pub time: BlockTime,
    pub finder: PublicKey,
    pub magic: Magic,
}

impl Block {
    pub fn new(
        version: BlockVersion,
        merkle_root: BlockHash,
        back_hash: BlockHash,
        time: BlockTime,
        finder: PublicKey,
        magic: Magic,
    ) -> Block {
        Block {
            version,
            merkle_root,
            back_hash,
            time,
            finder,
            magic,
        }
    }

    // pub fn get_user_data_change(&mut self, pk: &mut PublicKey) -> Result<i32, String> {
    //     let mut tmp_data = 0;
    //     for transaction_block in self.transaction_blocks.iter_mut() {
    //         tmp_data += transaction_block.get_user_data_change(pk)?;
    //     }
    //     Ok(tmp_data)
    // }
}

impl Serialize for Block {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        users: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<Block>, String> {
        let bytes_left = data.len() - *i;
        if bytes_left < Self::serialized_len() {
            return Err(format!(
                "Not enough bytes to deserialize block, found {} expected at least {}",
                bytes_left,
                Block::serialized_len()
            ));
        }
        let version = *BlockVersion::from_serialized(data, i, users)?;
        let merkle_root = *BlockHash::from_serialized(data, i, users)?;
        let back_hash = *BlockHash::from_serialized(data, i, users)?;
        let time = *BlockTime::from_serialized(data, i, users)?;
        let finder = *PublicKey::from_serialized(data, i, users)?;
        let magic = *Magic::from_serialized(data, i, users)?;

        Ok(Box::new(Block::new(
            version,
            merkle_root,
            back_hash,
            time,
            finder,
            magic,
        )))
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<usize, String> {
        let bytes_left = data.len() - *i;
        if bytes_left < Self::serialized_len() {
            return Err(format!(
                "Not enough bytes left to serialize block, expected at least {} found {}",
                Block::serialized_len(),
                bytes_left
            ));
        }
        let start_i = *i;
        self.version.serialize_into(data, i)?;
        self.merkle_root.serialize_into(data, i)?;
        self.back_hash.serialize_into(data, i)?;
        self.time.serialize_into(data, i)?;
        self.finder.serialize_into(data, i)?;
        self.magic.serialize_into(data, i)?;
        Ok(*i - start_i)
    }
}

impl StaticSized for Block {
    fn serialized_len() -> usize {
        BlockVersion::serialized_len()
            + merkle_forest::HASH_SIZE
            + BlockHash::serialized_len()
            + BlockTime::serialized_len()
            + PublicKey::serialized_len()
            + Magic::serialized_len()
    }
}
