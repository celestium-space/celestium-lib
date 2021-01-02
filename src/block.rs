use crate::{
    block_hash::BlockHash,
    block_version::BlockVersion,
    magic::Magic,
    merkle_forest,
    serialize::{Serialize, StaticSized},
    user::User,
};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, collections::HashMap, time::SystemTime};

const BLOCK_TIME_SIZE: usize = 4;

#[derive(Clone)]
pub struct BlockTime {
    value: [u8; BLOCK_TIME_SIZE],
}

impl BlockTime {
    pub fn now() -> Self {
        let secs_since_epoc = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut value = [0; BLOCK_TIME_SIZE];
        value[0] = (secs_since_epoc >> 24) as u8;
        value[1] = (secs_since_epoc >> 16) as u8;
        value[2] = (secs_since_epoc >> 8) as u8;
        value[3] = secs_since_epoc as u8;
        BlockTime { value }
    }
}

impl Ord for BlockTime {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl Eq for BlockTime {
    fn assert_receiver_is_total_eq(&self) {}
}

impl PartialOrd for BlockTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for BlockTime {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
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
        value.copy_from_slice(&data[*i..*i + Self::serialized_len()]);
        *i += Self::serialized_len();
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

#[derive(Clone)]
pub struct Block {
    pub version: BlockVersion,
    pub merkle_root: BlockHash,
    pub back_hash: BlockHash,
    pub time: BlockTime,
    pub magic: Magic,
}

impl Block {
    pub fn new(
        version: BlockVersion,
        merkle_root: BlockHash,
        back_hash: BlockHash,
        time: BlockTime,
        magic: Magic,
    ) -> Block {
        Block {
            version,
            merkle_root,
            back_hash,
            time,
            magic,
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        let mut self_serialized = vec![0u8; Block::serialized_len()];
        self.serialize_into(&mut self_serialized, &mut 0).unwrap();
        hash.copy_from_slice(Sha256::digest(&self_serialized).as_slice());
        hash
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
        let magic = *Magic::from_serialized(data, i, users)?;

        Ok(Box::new(Block::new(
            version,
            merkle_root,
            back_hash,
            time,
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
            + Magic::serialized_len()
    }
}
