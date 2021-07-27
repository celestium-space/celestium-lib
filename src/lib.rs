pub mod block;
pub mod block_hash;
pub mod block_version;
pub mod blockchain;
pub mod ec_key_serialization;
pub mod magic;
pub mod merkle_forest;
pub mod miner;
pub mod serialize;
pub mod transaction;
pub mod transaction_input;
pub mod transaction_output;
pub mod transaction_value;
pub mod transaction_varuint;
pub mod transaction_version;
pub mod wallet;

#[cfg(test)]
mod tests {
    use crate::{
        merkle_forest::MerkleForest, transaction::Transaction,
        transaction_varuint::TransactionVarUint,
    };
    use secp256k1::PublicKey;

    fn create_test_transaction(pk: PublicKey) -> (Transaction, MerkleForest<Transaction>) {
        let t0 = crate::transaction::Transaction::new(
            crate::transaction_version::TransactionVersion::default(),
            vec![],
            vec![crate::transaction_output::TransactionOutput::new(
                crate::transaction_value::TransactionValue::new_coin_transfer(100, 0).unwrap(),
                pk,
            )],
        );

        let tis = vec![crate::transaction_input::TransactionInput::new(
            t0.hash(),
            TransactionVarUint::from(0),
        )];

        let mut merkle_forest = MerkleForest::new_empty();
        merkle_forest.add_transactions(vec![t0]).unwrap();
        let tos = vec![crate::transaction_output::TransactionOutput::new(
            crate::transaction_value::TransactionValue::new_coin_transfer(100, 0).unwrap(),
            pk,
        )];
        (
            crate::transaction::Transaction::new(
                crate::transaction_version::TransactionVersion::default(),
                tis,
                tos,
            ),
            merkle_forest,
        )
    }

    #[test]
    fn transaction_not_mined_verify() {
        let (pk, _) = crate::wallet::Wallet::generate_ec_keys();
        let (transaction, _) = create_test_transaction(pk);
        assert!(!transaction.contains_enough_work());
    }

    #[test]
    fn transaction_sign_verify() {
        let (pk, sk) = crate::wallet::Wallet::generate_ec_keys();
        let (mut transaction, merkle_forest) = create_test_transaction(pk);
        transaction.sign(sk, 0).unwrap();
        transaction.verify(merkle_forest).unwrap();
    }

    #[test]
    fn transaction_no_sign_verify() {
        let (pk, _) = crate::wallet::Wallet::generate_ec_keys();
        let (mut transaction, merkle_forest) = create_test_transaction(pk);
        assert!(transaction.verify(merkle_forest).is_err());
    }

    #[test]
    fn var_uint_from_usize() {
        let var_uint = crate::transaction_varuint::TransactionVarUint::from(0x12345678);
        assert_eq!(
            var_uint.value,
            [0b10000001, 0b10010001, 0b11010001, 0b10101100, 0b01111000]
        );
        assert_eq!(var_uint.get_value(), 0x12345678);
    }

    #[test]
    fn magic_increase1() {
        let mut var_uint = crate::transaction_varuint::TransactionVarUint::from(0x12345678);
        let len = var_uint.value.len();
        crate::magic::Magic::increase(&mut var_uint.value, len);
        assert_eq!(var_uint.get_value(), 0x12345679)
    }

    #[test]
    fn magic_increase2() {
        let mut var_uint = crate::transaction_varuint::TransactionVarUint::from(0xff00ff);
        let len = var_uint.value.len();
        crate::magic::Magic::increase(&mut var_uint.value, len);
        assert_eq!(var_uint.get_value(), 0xff0100)
    }

    #[test]
    fn magic_increase3() {
        let mut var_uint = crate::transaction_varuint::TransactionVarUint::from(0xffffff);
        let len = var_uint.value.len();
        crate::magic::Magic::increase(&mut var_uint.value, len);
        assert_eq!(var_uint.get_value(), 0x1000000)
    }

    #[test]
    fn magic_increase4() {
        let mut var_uint = crate::transaction_varuint::TransactionVarUint::from(0);
        let len = var_uint.value.len();
        crate::magic::Magic::increase(&mut var_uint.value, len);
        assert_eq!(var_uint.get_value(), 0x1)
    }

    #[test]
    fn magic_len_test() {
        let var_uint = crate::transaction_varuint::TransactionVarUint::from(
            crate::wallet::DEFAULT_PAR_WORK as usize,
        );
        let test_len = var_uint.value.len();
        for i in 1..crate::wallet::DEFAULT_N_THREADS {
            let var_uint = crate::transaction_varuint::TransactionVarUint::from(
                (i * crate::wallet::DEFAULT_PAR_WORK) as usize,
            );
            assert_eq!(var_uint.value.len(), test_len)
        }
        let var_uint = crate::transaction_varuint::TransactionVarUint::from(
            ((crate::wallet::DEFAULT_N_THREADS + 1) * crate::wallet::DEFAULT_PAR_WORK) as usize,
        );
        assert_eq!(var_uint.value.len(), test_len + 1)
    }

    #[test]
    fn wallet_generation_and_mining_test() {
        match crate::wallet::Wallet::generate_init_blockchain(true) {
            Ok(wallet) => match wallet.to_binary() {
                Ok(bw) => {
                    println!("{:x?}", bw.blockchain_bin);
                    assert!(true)
                }
                Err(e) => {
                    println!("{}", e);
                    assert!(false)
                }
            },
            Err(e) => {
                println!("{}", e);
                assert!(false)
            }
        }
    }
}
