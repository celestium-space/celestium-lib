use crate::serialize::Serialize;
use std::fmt::{self, Display, Formatter};

pub struct Magic {
    pub value: [u8; 8],
}

impl Magic {
    pub fn new(data: u64) -> Magic {
        let mut value = [0u8; 8];
        value[0] = (data >> 56) as u8;
        value[1] = (data >> 48) as u8;
        value[2] = (data >> 40) as u8;
        value[3] = (data >> 32) as u8;
        value[4] = (data >> 24) as u8;
        value[5] = (data >> 16) as u8;
        value[6] = (data >> 8) as u8;
        value[7] = data as u8;
        Magic { value }
    }

    pub fn increase(&mut self) {
        self.value[7] += 1;
        if self.value[7] == 0 {
            self.value[6] += 1;
            if self.value[6] == 0 {
                self.value[5] += 1;
                if self.value[5] == 0 {
                    self.value[4] += 1;
                    if self.value[4] == 0 {
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
            }
        }
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
        if data.len() - *i < 8 {
            return Err(format!(
                "Cannot create magic, expected at least 8 bytes got {}",
                data.len() - *i
            ));
        };
        let mut value = [0u8; 8];
        value.copy_from_slice(&data[*i..*i + 8]);
        *i += 8;
        Ok(Box::new(Magic { value }))
    }

    fn serialize_into(&self, buffer: &mut [u8], i: &mut usize) -> Result<usize, String> {
        if buffer.len() - *i < 8 {
            return Err(format!(
                "Cannot serialize magic, expected buffer with least 8 bytes left got {}",
                buffer.len() - *i
            ));
        };
        buffer[*i..*i + 8].copy_from_slice(&self.value);
        *i += 8;
        Ok(8)
    }

    fn serialized_len(&self) -> Result<usize, String> {
        Ok(8)
    }
}
