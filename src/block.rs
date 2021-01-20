use crate::{
    block_hash::BlockHash,
    block_version::BlockVersion,
    serialize::{DynamicSized, Serialize, StaticSized},
    transaction_varuint::TransactionVarUint,
};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Block {
    pub version: BlockVersion,
    pub merkle_root: BlockHash,
    pub back_hash: BlockHash,
    pub magic: TransactionVarUint,
}

impl Block {
    pub fn new(
        version: BlockVersion,
        merkle_root: BlockHash,
        back_hash: BlockHash,
        magic: TransactionVarUint,
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
        let mut self_serialized = vec![0u8; self.serialized_len()];
        self.serialize_into(&mut self_serialized, &mut 0).unwrap();
        hash.copy_from_slice(Sha256::digest(&self_serialized).as_slice());
        hash
    }
}

impl Serialize for Block {
    fn from_serialized(data: &[u8], i: &mut usize) -> Result<Box<Block>, String> {
        let version = *BlockVersion::from_serialized(data, i)?;
        let merkle_root = *BlockHash::from_serialized(data, i)?;
        let back_hash = *BlockHash::from_serialized(data, i)?;
        let magic = *TransactionVarUint::from_serialized(data, i)?;

        Ok(Box::new(Block::new(version, merkle_root, back_hash, magic)))
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<(), String> {
        let bytes_left = data.len() - *i;
        if bytes_left < self.serialized_len() {
            return Err(format!(
                "Not enough bytes left to serialize block, expected at least {} found {}",
                self.serialized_len(),
                bytes_left
            ));
        }
        self.version.serialize_into(data, i)?;
        self.merkle_root.serialize_into(data, i)?;
        self.back_hash.serialize_into(data, i)?;
        self.magic.serialize_into(data, i)?;
        Ok(())
    }
}

impl DynamicSized for Block {
    fn serialized_len(&self) -> usize {
        BlockVersion::serialized_len()
            + BlockHash::serialized_len()
            + BlockHash::serialized_len()
            + self.magic.serialized_len()
    }
}
