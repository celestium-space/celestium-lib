use crate::{
    serialize::{Serialize, StaticSized},
    wallet::HASH_SIZE,
};
use std::{
    fmt::{self, Display, Formatter},
    hash::Hash,
};

#[derive(Clone)]
pub struct TransactionHash {
    value: [u8; HASH_SIZE],
}

impl TransactionHash {
    pub fn new_unworked() -> TransactionHash {
        TransactionHash {
            value: [0xff; HASH_SIZE],
        }
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
            hash[0] == 0x00 && hash[1] == 0x00 && hash[2] == 0x00
        }
    }

    pub fn is_zero_block(&self) -> bool {
        self.value == [0; HASH_SIZE]
    }

    pub fn hash(&self) -> [u8; HASH_SIZE] {
        self.value
    }
}

impl From<[u8; HASH_SIZE]> for TransactionHash {
    fn from(value: [u8; HASH_SIZE]) -> Self {
        TransactionHash { value }
    }
}

impl Default for TransactionHash {
    fn default() -> Self {
        TransactionHash {
            value: [0; HASH_SIZE],
        }
    }
}

impl PartialEq for TransactionHash {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
impl Eq for TransactionHash {}

impl Hash for TransactionHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl Display for TransactionHash {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "[0x{}]", hex::encode(self.value))
    }
}

impl Serialize for TransactionHash {
    fn from_serialized(data: &[u8], i: &mut usize) -> Result<Box<TransactionHash>, String> {
        if data.len() - *i < HASH_SIZE {
            return Err(format!(
                "Cannot deserialize hash, expected buffer with least {} bytes left got {}",
                HASH_SIZE,
                data.len() - *i
            ));
        };
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&data[*i..*i + HASH_SIZE]);
        *i += HASH_SIZE;
        Ok(Box::new(TransactionHash { value: hash }))
    }

    fn serialize_into(&self, buffer: &mut [u8], i: &mut usize) -> Result<(), String> {
        buffer[*i..*i + HASH_SIZE].copy_from_slice(&self.value);
        *i += TransactionHash::serialized_len();
        Ok(())
    }
}

impl StaticSized for TransactionHash {
    fn serialized_len() -> usize {
        HASH_SIZE
    }
}
