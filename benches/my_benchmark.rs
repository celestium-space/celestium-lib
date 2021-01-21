use celestium::{transaction_value::TransactionValue, wallet::Wallet};
use criterion::{criterion_group, criterion_main, Criterion};

fn criterion_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("Single threaded mining");
    group.sample_size(10);
    let (pk2, _) = Wallet::generate_ec_keys();
    let mut wallet = Wallet::generate_init_blockchain(true).unwrap();
    group.bench_function("Mining speed", |b| {
        b.iter(|| {
            let value = TransactionValue::new_coin_transfer(500, 10).unwrap();
            wallet.send(pk2, value).unwrap();
            let mut miner = wallet
                .miner_from_off_chain_transactions(0, u64::MAX)
                .unwrap();
            while miner.do_work().is_pending() {}
        })
    });
    group.finish();
    let mut group = c.benchmark_group("Multi threaded mining");
    group.sample_size(10);
    group.bench_function("Mining speed", |b| {
        b.iter(|| {
            Wallet::generate_init_blockchain(true).unwrap();
        })
    });
    group.finish();
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
