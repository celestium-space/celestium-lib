use crate::{
    block::Block,
    block_hash::BlockHash,
    block_version::BlockVersion,
    magic::Magic,
    serialize::{DynamicSized, Serialize},
    transaction::Transaction,
    transaction_varuint::TransactionVarUint,
};
//use crypto::{digest::Digest, sha2::Sha256};
use sha2::{Digest, Sha256};
use std::{ops::Range, task::Poll};

#[derive(Clone)]
pub struct Miner {
    my_serialized_block: Vec<u8>,
    i: u64,
    end: u64,
    pub transactions: Vec<Transaction>,
    pub magic_start: usize,
    pub magic_len: usize,
}

impl Miner {
    pub fn new_from_hashes(
        merkle_root: BlockHash,
        back_hash: BlockHash,
        transactions: Vec<Transaction>,
        start: u64,
        end: u64,
    ) -> Result<Self, String> {
        let version = BlockVersion::default();
        let magic = TransactionVarUint::from(start as usize);
        let block = Block::new(version, merkle_root, back_hash, magic);
        Miner::new_ranged(block, start..end, transactions)
    }

    pub fn new_ranged(
        block: Block,
        range: Range<u64>,
        transactions: Vec<Transaction>,
    ) -> Result<Self, String> {
        let magic_len = block.magic.serialized_len();
        let block_len = block.serialized_len();
        let mut my_serialized_block = vec![0u8; block_len - magic_len + 8];
        block.serialize_into(&mut my_serialized_block, &mut 0)?;
        Ok(Miner {
            my_serialized_block,
            i: range.start,
            end: range.end,
            transactions,
            magic_start: block_len - magic_len,
            magic_len,
        })
    }

    pub fn do_work(&mut self) -> Poll<Option<Block>> {
        let magic_end = self.magic_start + self.magic_len;
        let hash = Sha256::digest(&self.my_serialized_block[0..magic_end]);
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
