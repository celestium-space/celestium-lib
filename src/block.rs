use crate::{
    block_hash::BlockHash,
    block_version::BlockVersion,
    magic::Magic,
    merkle_forest,
    serialize::{Serialize, StaticSized},
};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Clone)]
pub struct Block {
    pub version: BlockVersion,
    pub merkle_root: BlockHash,
    pub back_hash: BlockHash,
    pub magic: Magic,
}

impl Block {
    pub fn new(
        version: BlockVersion,
        merkle_root: BlockHash,
        back_hash: BlockHash,
        magic: Magic,
    ) -> Block {
        Block {
            version,
            merkle_root,
            back_hash,
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
        let magic = *Magic::from_serialized(data, i, users)?;

        Ok(Box::new(Block::new(version, merkle_root, back_hash, magic)))
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<(), String> {
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
        self.magic.serialize_into(data, i)?;
        Ok(())
    }
}

impl StaticSized for Block {
    fn serialized_len() -> usize {
        BlockVersion::serialized_len()
            + merkle_forest::HASH_SIZE
            + BlockHash::serialized_len()
            + Magic::serialized_len()
    }
}
