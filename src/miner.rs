// use crate::magic::Magic;

// struct Miner {
//     my_serialized_block: Vec<u8>,
//     i: u64,
//     end: u64,
//     current_magic: Magic,
// }

// impl Miner {
//     pub fn new(serialized_block: Vec<u8>) -> Self {
//         Miner::new_ranged(serialized_block, 0u64..u64::MAX)
//     }

//     pub fn new_ranged(serialized_block: Vec<u8>, range: Range<u64>) -> Self {
//         let block_len = serialized_block.len();
//         let magic_byte_count = 1usize;
//         let my_serialized_block = vec![0u8; block_len + magic_byte_count];
//         my_serialized_block[..my_serialized_block.len() - 1].copy_from_slice(&serialized_block);
//         let mut magic = Magic::new(range.start as u64);
//         Miner {
//             my_serialized_block,
//             i: range.start,
//             end: range.end,
//             current_magic: magic,
//         }
//     }
// }

// impl Future for Miner {
//     fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Vec<u8>> {
//         self.current_magic.increase();
//         let magic_byte_count = self.current_magic.serialized_len().unwrap();
//         let block_len = self.my_serialized_block.len();
//         self.current_magic
//             .serialize_into(
//                 &mut self.my_serialized_block,
//                 &mut (block_len - magic_byte_count),
//             )
//             .unwrap();
//         let hash = *BlockHash::from_serialized(
//             Sha256::digest(&self.my_serialized_block).as_slice(),
//             &mut 0,
//             &mut HashMap::new(),
//         )
//         .unwrap();
//         if hash.contains_enough_work() {
//             return Ready(self.my_serialized_block);
//         }
//         Pending
//     }

//     type Output = Magic;
// }
