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
    my_serialized_block: Vec<u8>,
    i: u64,
    end: u64,
    pub magic_start: usize,
    pub magic_len: usize,
}

impl Miner {
    pub fn new_ranged(block: Block, range: Range<u64>) -> Result<Self, String> {
        let mut magic_len = block.magic.serialized_len();
        let block_len = block.serialized_len();
        let magic_start = block_len - magic_len;
        let mut my_serialized_block = vec![0u8; magic_start + 8];
        let mut tmp_magic_start = magic_start;
        block.serialize_into(&mut my_serialized_block, &mut 0)?;
        let var_uint: TransactionVarUint = TransactionVarUint::from(range.start as usize);
        var_uint.serialize_into(&mut my_serialized_block, &mut tmp_magic_start)?;
        magic_len = var_uint.value.len();
        Ok(Miner {
            my_serialized_block,
            i: range.start,
            end: range.end,
            magic_start,
            magic_len,
        })
    }

    pub fn do_work(&mut self) -> Poll<Option<Block>> {
        let magic_end = self.magic_start + self.magic_len;
        let hash = Sha3_256::digest(&self.my_serialized_block[0..magic_end]);
        if self.i <= self.end && !BlockHash::contains_enough_work(&hash) {
            self.magic_len = Magic::increase(
                &mut self.my_serialized_block[self.magic_start..],
                self.magic_len,
            );
            self.i += 1;
            Poll::Pending
        } else if self.i <= self.end {
            let block =
                *Block::from_serialized(&self.my_serialized_block[0..magic_end], &mut 0).unwrap();
            Poll::Ready(Some(block))
        } else {
            Poll::Ready(None)
        }
    }
}
