use crate::{
    serialize::{Serialize, StaticSized},
    user::User,
};
use secp256k1::PublicKey;
use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
};

const BLOCK_HASH_SIZE: usize = 32;

#[derive(Clone)]
pub struct BlockHash {
    value: [u8; 32],
}

impl BlockHash {
    pub fn new_unworked() -> BlockHash {
        BlockHash { value: [0xff; 32] }
    }

    pub fn contains_enough_work(&self) -> bool {
        if self.value[0] == 0 && self.value[1] == 0 {
            // && self.value[2] == 0 && self.value[3] == 0 {
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

impl Display for BlockHash {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
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
        *i += BlockHash::serialized_len();
        Ok(BlockHash::serialized_len())
    }
}

impl StaticSized for BlockHash {
    fn serialized_len() -> usize {
        BLOCK_HASH_SIZE
    }
}
