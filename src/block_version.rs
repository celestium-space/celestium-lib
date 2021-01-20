use crate::serialize::{Serialize, StaticSized};

#[derive(Clone)]
pub struct BlockVersion {
    pub value: [u8; 1],
}

impl BlockVersion {
    pub fn default() -> Self {
        BlockVersion { value: [0] }
    }
}

impl Serialize for BlockVersion {
    fn from_serialized(data: &[u8], i: &mut usize) -> Result<Box<Self>, String> {
        if data[*i] != 0 {
            Err(format!("Expected block version 0 found {}", data[*i]))
        } else {
            *i += 1;
            Ok(Box::new(BlockVersion {
                value: [data[*i - 1]],
            }))
        }
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<(), String> {
        data[*i] = self.value[0];
        *i += 1;
        Ok(())
    }
}

impl StaticSized for BlockVersion {
    fn serialized_len() -> usize {
        1
    }
}
