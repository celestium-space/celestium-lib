use celestium::{transaction_value::TransactionValue, wallet::Wallet};
use criterion::{criterion_group, criterion_main, Criterion};

fn single_core_mining_speed(c: &mut Criterion) {
    let mut group = c.benchmark_group("Single threaded mining");
    group.sample_size(10);
    //     .measurement_time(Duration::new(2000, 0));
    group.bench_function("Mining speed", |b| {
        b.iter(|| {
            let (pk2, _) = Wallet::generate_ec_keys();
            let mut wallet = Wallet::generate_init_blockchain(true).unwrap();
            let value = TransactionValue::new_coin_transfer(500, 10).unwrap();
            wallet.send(pk2, value).unwrap();
            let mut miner = wallet
                .miner_from_off_chain_transactions(0, u64::MAX)
                .unwrap();
            while miner.do_work().is_pending() {}
        })
    });
    group.finish();
}

criterion_group!(benches, single_core_mining_speed);
criterion_main!(benches);
