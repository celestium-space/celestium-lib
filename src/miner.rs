use crate::{
    block::Block,
    block_hash::BlockHash,
    magic::Magic,
    serialize::{DynamicSized, Serialize},
    transaction_varuint::TransactionVarUint,
};
use sha3::{Digest, Sha3_256};
use std::{ops::Range, task::Poll};

#[derive(Clone)]
pub struct Miner {
    data: Vec<u8>,
    i: u64,
    end: u64,
    pub magic_start: usize,
    pub magic_len: usize,
}

impl Miner {
    pub fn new_ranged(data: Vec<u8>, range: Range<u64>) -> Result<Self, String> {
        let mut data_with_magic = vec![0u8; data.len() + 8];
        data_with_magic[0..data.len()].copy_from_slice(&data);
        let var_uint: TransactionVarUint = TransactionVarUint::from(range.start as usize);
        var_uint.serialize_into(&mut data_with_magic, &mut data.len())?;
        let magic_len = var_uint.value.len();
        Ok(Miner {
            data: data_with_magic,
            i: range.start,
            end: range.end,
            magic_start: data.len(),
            magic_len,
        })
    }

    pub fn from_block(block: Block, range: Range<u64>) -> Result<Self, String> {
        let mut serialized_block = vec![0u8; block.serialized_len()];
        block.serialize_into(&mut serialized_block, &mut 0)?;
        Miner::new_ranged(
            serialized_block[0..serialized_block.len() - block.magic.serialized_len()].to_vec(),
            range,
        )
    }

    pub fn do_work(&mut self) -> Poll<Option<Vec<u8>>> {
        let magic_end = self.magic_start + self.magic_len;
        if self.i <= self.end
            && !BlockHash::contains_enough_work(&Sha3_256::digest(&self.data[0..magic_end]))
        {
            self.magic_len = Magic::increase(&mut self.data[self.magic_start..], self.magic_len);
            self.i += 1;
            Poll::Pending
        } else if self.i <= self.end {
            Poll::Ready(Some(self.data[0..magic_end].to_vec()))
        } else {
            Poll::Ready(None)
        }
    }
}
