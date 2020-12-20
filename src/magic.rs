use crate::serialize::Serialize;
use std::{
    cmp::Ordering,
    fmt::{self, Display, Formatter},
};

pub struct Magic {
    pub value: [u8; 4],
}

impl Magic {
    pub fn new(data: u32) -> Magic {
        let mut value = [0u8; 4];
        value[0] = (data >> 24) as u8;
        value[1] = (data >> 16) as u8;
        value[2] = (data >> 8) as u8;
        value[3] = (data) as u8;
        Magic { value }
    }

    pub fn increase(&mut self) {
        self.value[3] += 1;
        if self.value[3] == 0 {
            self.value[2] += 1;
            if self.value[2] == 0 {
                self.value[1] += 1;
                if self.value[1] == 0 {
                    self.value[0] += 1;
                }
            }
        }
    }
}

impl Ord for Magic {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u32::from_be_bytes(self.value).cmp(&u32::from_be_bytes(other.value))
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
        u32::from_be_bytes(self.value) == u32::from_be_bytes(other.value)
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
        if data.len() - *i < 4 {
            return Err(format!(
                "Cannot create magic, expected at least 4 bytes got {}",
                data.len() - *i
            ));
        };
        let mut value = [0u8; 4];
        value.copy_from_slice(&data[*i..*i + 4]);
        *i += 4;
        Ok(Box::new(Magic { value }))
    }

    fn serialize_into(&self, buffer: &mut [u8], i: &mut usize) -> Result<usize, String> {
        if buffer.len() - *i < 4 {
            return Err(format!(
                "Cannot serialize magic, expected buffer with least 4 bytes left got {}",
                buffer.len() - *i
            ));
        };
        buffer[*i..*i + 4].copy_from_slice(&self.value);
        *i += 4;
        Ok(4)
    }

    fn serialized_len(&self) -> Result<usize, String> {
        Ok(4)
    }
}
