use crate::serialize::Serialize;
use std::{
    cmp::Ordering,
    fmt::{self, Display, Formatter},
};

const MAGIC_LEN: usize = 8;

pub struct Magic {
    pub value: [u8; MAGIC_LEN],
}

impl Magic {
    pub fn new(data: u64) -> Magic {
        let value = [0; MAGIC_LEN];
        let i = 0;
        for i in MAGIC_LEN - 1..0 {
            value[i] = data as u8;
            data >>= 8;
        }
        Magic { value }
    }

    pub fn increase(&mut self) {
        self.increase_rec(self.value.len() - 1)
    }

    fn increase_rec(&mut self, i: usize) {
        self.value[i] += 1;
        if self.value[i] == 0 {
            self.increase_rec(i - 1)
        }
    }
}

impl Ord for Magic {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u64::from_be_bytes(self.value).cmp(&u64::from_be_bytes(other.value))
    }
}

impl Eq for Magic {
    fn assert_receiver_is_total_eq(&self) {}
}

impl PartialOrd for Magic {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Magic {
    fn eq(&self, other: &Self) -> bool {
        u64::from_be_bytes(self.value) == u64::from_be_bytes(other.value)
    }
}

impl Display for Magic {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:x?}", self.value)
    }
}

impl Serialize for Magic {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        _: &mut std::collections::HashMap<secp256k1::PublicKey, crate::user::User>,
    ) -> Result<Box<Self>, String> {
        if data.len() - *i < MAGIC_LEN {
            return Err(format!(
                "Cannot create magic, expected at least {} bytes got {}",
                MAGIC_LEN,
                data.len() - *i
            ));
        };
        let mut value = [0u8; MAGIC_LEN];
        value.copy_from_slice(&data[*i..*i + MAGIC_LEN]);
        *i += MAGIC_LEN;
        Ok(Box::new(Magic { value }))
    }

    fn serialize_into(&self, buffer: &mut [u8], i: &mut usize) -> Result<usize, String> {
        if buffer.len() - *i < MAGIC_LEN {
            return Err(format!(
                "Cannot serialize magic, expected buffer with least {} bytes left got {}",
                MAGIC_LEN,
                buffer.len() - *i
            ));
        };
        buffer[*i..*i + MAGIC_LEN].copy_from_slice(&self.value);
        *i += MAGIC_LEN;
        Ok(MAGIC_LEN)
    }

    fn serialized_len(&self) -> Result<usize, String> {
        Ok(MAGIC_LEN)
    }
}
