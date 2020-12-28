use crate::{
    block::{Block, BlockTime},
    block_hash::BlockHash,
    block_version::BlockVersion,
    magic::Magic,
    merkle_forest::MerkleForest,
    serialize::{Serialize, StaticSized},
    transaction::Transaction,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    future::Future,
    ops::Range,
    task::{Context, Poll},
};

pub struct Miner {
    my_serialized_block: Vec<u8>,
    i: u64,
    end: u64,
    current_magic: Magic,
}

impl Miner {
    pub fn new(serialized_block: Vec<u8>) -> Self {
        Miner::new_ranged(serialized_block, 0u64..u64::MAX)
    }

    pub fn new_from_mf_leafs(
        leafs: Vec<Transaction>,
        back_hash: BlockHash,
    ) -> Result<Self, String> {
        let version = *BlockVersion::from_serialized(&[0, 0, 0, 0], &mut 0, &mut HashMap::new())?;
        let mut merkle_tree = MerkleForest::new_empty();
        merkle_tree.add_transactions(leafs)?;
        let merkle_root = *BlockHash::from_serialized(
            &merkle_tree.create_tree_from_leafs()?,
            &mut 0,
            &mut HashMap::new(),
        )?;
        let time = BlockTime::now();
        let magic = Magic::new(0);
        let block = Block::new(version, merkle_root, back_hash, time, magic);
        let mut block_serialized = vec![0u8; Block::serialized_len()];
        block.serialize_into(&mut block_serialized, &mut 0);
        Ok(Miner::new(block_serialized))
    }

    pub fn new_ranged(serialized_block: Vec<u8>, range: Range<u64>) -> Self {
        let block_len = serialized_block.len();
        let magic_byte_count = 1usize;
        let mut my_serialized_block = vec![0u8; block_len + magic_byte_count];
        my_serialized_block[0..block_len].copy_from_slice(&serialized_block);
        let magic = Magic::new(range.start as u64);
        Miner {
            my_serialized_block,
            i: range.start,
            end: range.end,
            current_magic: magic,
        }
    }

    pub fn do_work(&mut self) -> Poll<Option<Magic>> {
        self.current_magic.increase();
        self.i += 1;
        let mut magic_start = self.my_serialized_block.len() - Magic::serialized_len();
        let mut serialized_magic = vec![0u8; Magic::serialized_len()];
        self.current_magic
            .serialize_into(&mut serialized_magic, &mut magic_start)
            .unwrap();
        self.my_serialized_block[magic_start..Magic::serialized_len()]
            .copy_from_slice(&serialized_magic);
        let hash = *BlockHash::from_serialized(
            Sha256::digest(&self.my_serialized_block).as_slice(),
            &mut 0,
            &mut HashMap::new(),
        )
        .unwrap();
        if hash.contains_enough_work() {
            Poll::Ready(Some(self.current_magic.clone()))
        } else if self.i < self.end {
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }
}

impl Future for Miner {
    fn poll(mut self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Magic>> {
        self.do_work()
    }

    type Output = Option<Magic>;
}
