use crate::{
    block::Block,
    block_hash::BlockHash,
    block_version::BlockVersion,
    magic::Magic,
    serialize::{DynamicSized, Serialize, StaticSized},
    transaction::Transaction,
    transaction_varuint::TransactionVarUint,
};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    ops::Range,
    task::{Context, Poll},
};

#[derive(Clone)]
pub struct Miner {
    my_serialized_block: Vec<u8>,
    i: u64,
    end: u64,
    current_magic: Magic,
    pub transactions: Vec<Transaction>,
}

impl Miner {
    // pub fn new(serialized_block: Vec<u8>, transactions: Vec<Transaction>) -> Self {
    //     Miner::new_ranged(serialized_block, 0u64..u64::MAX, transactions)
    // }

    pub fn new_from_hashes(
        merkle_root: BlockHash,
        back_hash: BlockHash,
        transactions: Vec<Transaction>,
        start: u64,
        end: u64,
    ) -> Result<Self, String> {
        let version = *BlockVersion::from_serialized(&[0, 0, 0, 0], &mut 0)?;
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

    // pub fn new_from_mf_leafs(
    //     leafs: Vec<Transaction>,
    //     back_hash: BlockHash,
    // ) -> Result<Self, String> {
    //     let version = *BlockVersion::from_serialized(&[0, 0, 0, 0], &mut 0, &mut HashMap::new())?;
    //     let mut merkle_tree = MerkleForest::new_empty();
    //     merkle_tree.add_transactions(leafs)?;
    //     let merkle_root = *BlockHash::from_serialized(
    //         &merkle_tree.create_tree_from_leafs()?,
    //         &mut 0,
    //         &mut HashMap::new(),
    //     )?;
    //     let time = BlockTime::now();
    //     let magic = Magic::new(0);
    //     let block = Block::new(version, merkle_root, back_hash, time, magic);
    //     let mut block_serialized = vec![0u8; Block::serialized_len()];
    //     block.serialize_into(&mut block_serialized, &mut 0)?;
    //     Ok(Miner::new(block_serialized))
    // }

    pub fn new_ranged(
        serialized_block: Vec<u8>,
        range: Range<u64>,
        transactions: Vec<Transaction>,
    ) -> Self {
        let block_len = serialized_block.len();
        let mut my_serialized_block = vec![0u8; block_len];
        my_serialized_block[0..block_len].copy_from_slice(&serialized_block);
        let magic = Magic::new(range.start as u64);
        Miner {
            my_serialized_block,
            i: range.start,
            end: range.end,
            current_magic: magic,
            transactions,
        }
    }

    pub fn do_work(&mut self) -> Poll<Option<Block>> {
        let magic_start = self.my_serialized_block.len() - Magic::serialized_len() - 1;
        let mut serialized_magic = vec![0u8; Magic::serialized_len()];
        self.current_magic
            .serialize_into(&mut serialized_magic, &mut 0)
            .unwrap();
        self.my_serialized_block[magic_start..magic_start + Magic::serialized_len()]
            .copy_from_slice(&serialized_magic);
        let hash = *BlockHash::from_serialized(
            Sha256::digest(&self.my_serialized_block).as_slice(),
            &mut 0,
        )
        .unwrap();
        if hash.contains_enough_work() {
            let block = *Block::from_serialized(&self.my_serialized_block, &mut 0).unwrap();
            Poll::Ready(Some(block))
        } else if self.i < self.end {
            self.current_magic.increase();
            self.i += 1;
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }
}

impl Future for Miner {
    fn poll(mut self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Block>> {
        self.do_work()
    }

    type Output = Option<Block>;
}
