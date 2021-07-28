use celestium::{
    block::Block,
    block_hash::BlockHash,
    block_version::BlockVersion,
    transaction_varuint::TransactionVarUint,
    wallet::{self, Wallet},
};
use criterion::{criterion_group, criterion_main, Criterion};

fn criterion_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("Multi threaded mining");
    group.bench_function("Mining speed", |b| {
        b.iter(|| {
            let (pk, sk) = Wallet::generate_ec_keys();
            let wallet = Wallet::new(pk, sk, true);
            wallet
                .mine_block(
                    wallet::DEFAULT_N_THREADS,
                    wallet::DEFAULT_PAR_WORK,
                    Block::new(
                        BlockVersion::default(),
                        BlockHash::new_unworked(),
                        BlockHash::new_unworked(),
                        TransactionVarUint::from(0),
                    ),
                )
                .unwrap();
        })
    });
    group.sample_size(10);
    group.finish();
    // let mut group = c.benchmark_group("Single threaded mining");
    // let (pk2, _) = Wallet::generate_ec_keys();
    // let mut wallet = Wallet::generate_init_blockchain(true).unwrap();
    // group.bench_function("Mining speed", |b| {
    //     b.iter(|| {
    //         let value = TransactionValue::new_coin_transfer(500, 10).unwrap();
    //         wallet.send(pk2, value).unwrap();
    //         let (block, _) = wallet.mining_data_from_off_chain_transactions().unwrap();
    //         let mut serialized_block = vec![0u8; block.serialized_len()];
    //         block.serialize_into(&mut serialized_block, &mut 0).unwrap();
    //         let mut miner = Miner::new_ranged(
    //             serialized_block[0..serialized_block.len() - block.magic.serialized_len()].to_vec(),
    //             0..u64::MAX,
    //         )
    //         .unwrap();
    //         while miner.do_work().is_pending() {}
    //     })
    // });
    // group.finish();
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
