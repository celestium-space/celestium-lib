use crate::{
    block::Block,
    block_hash::BlockHash,
    magic::Magic,
    serialize::{DynamicSized, Serialize},
    transaction::Transaction,
    transaction_varuint::TransactionVarUint,
};
use crypto::{digest::Digest, sha2::Sha256};
use std::{ops::Range, task::Poll};

#[derive(Clone)]
pub struct Miner {
    my_serialized_block: Vec<u8>,
    i: u64,
    end: u64,
    pub transactions: Vec<Transaction>,
    magic_start: usize,
    magic_len: usize,
}

impl Miner {
    pub fn new_from_hashes(
        merkle_root: BlockHash,
        back_hash: BlockHash,
        transactions: Vec<Transaction>,
        start: u64,
        end: u64,
    ) -> Result<Self, String> {
        let version = TransactionVarUint::from(0);
        let magic = TransactionVarUint::from(0);
        let block = Block::new(version, merkle_root, back_hash, magic);
        let mut block_serialized = vec![0u8; block.serialized_len()];
        block.serialize_into(&mut block_serialized, &mut 0)?;
        Ok(Miner::new_ranged(
            block_serialized,
            start..end,
            transactions,
        ))
    }

    pub fn new_ranged(
        serialized_block: Vec<u8>,
        range: Range<u64>,
        transactions: Vec<Transaction>,
    ) -> Self {
        let block_len = serialized_block.len();
        let mut my_serialized_block = vec![0u8; block_len + 7];
        my_serialized_block[0..block_len].copy_from_slice(&serialized_block);
        let magic_start = block_len - 1;
        Miner {
            my_serialized_block,
            i: range.start,
            end: range.end,
            transactions,
            magic_start,
            magic_len: 1,
        }
    }

    pub fn do_work(&mut self) -> Poll<Option<Block>> {
        let magic_end = self.magic_start + self.magic_len;
        let mut hasher = Sha256::new();
        hasher.input(&self.my_serialized_block[0..magic_end]);
        let mut hash = [0; 32];
        hasher.result(&mut hash);
        if self.i < self.end && !BlockHash::contains_enough_work(&hash) {
            self.magic_len = Magic::increase(
                &mut self.my_serialized_block[self.magic_start..],
                self.magic_len,
            );
            self.i += 1;
            Poll::Pending
        } else if self.i < self.end {
            let block =
                *Block::from_serialized(&self.my_serialized_block[0..magic_end], &mut 0).unwrap();
            Poll::Ready(Some(block))
        } else {
            Poll::Ready(None)
        }
    }
}

// impl Future for Miner {
//     fn poll(mut self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Block>> {
//         self.do_work()
//     }

//     type Output = Option<Block>;
// }
