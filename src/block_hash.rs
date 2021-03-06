use crate::{
    serialize::{Serialize, StaticSized},
    wallet::HASH_SIZE,
};
use std::{
    fmt::{self, Display, Formatter},
    hash::Hash,
};

#[derive(Clone)]
pub struct BlockHash {
    value: [u8; 32],
}

impl BlockHash {
    pub fn new_unworked() -> BlockHash {
        BlockHash { value: [0xff; 32] }
    }

    pub fn contains_enough_work(hash: &[u8]) -> bool {
        // make proof-of-work easier if this feature is set at compile time
        // really only useful for development and testing
        #[cfg(feature = "mining-ez-mode")]
        {
            hash[0] == 0 && hash[1] == 0
        }
        #[cfg(not(feature = "mining-ez-mode"))]
        {
            hash[0] == 0 && hash[1] == 0 && hash[2] == 0 && hash[3] == 0
        }
    }

    pub fn is_zero_block(&self) -> bool {
        self.value == [0; 32]
    }

    pub fn hash(&self) -> [u8; HASH_SIZE] {
        self.value
    }
}

impl From<[u8; HASH_SIZE]> for BlockHash {
    fn from(value: [u8; HASH_SIZE]) -> Self {
        BlockHash { value }
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
impl Eq for BlockHash {}

impl Hash for BlockHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl Display for BlockHash {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "[0x{}]", hex::encode(self.value))
    }
}

impl Serialize for BlockHash {
    fn from_serialized(data: &[u8], i: &mut usize) -> Result<Box<BlockHash>, String> {
        if data.len() - *i < 32 {
            return Err(format!(
                "Cannot deserialize hash, expected buffer with least 32 bytes left got {}",
                data.len() - *i
            ));
        };
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[*i..*i + 32]);
        *i += 32;
        Ok(Box::new(BlockHash { value: hash }))
    }

    fn serialize_into(&self, buffer: &mut [u8], i: &mut usize) -> Result<(), String> {
        buffer[*i..*i + 32].copy_from_slice(&self.value);
        *i += BlockHash::serialized_len();
        Ok(())
    }
}

impl StaticSized for BlockHash {
    fn serialized_len() -> usize {
        HASH_SIZE
    }
}
