use crate::{
    serialize::Serialize, transaction_value::TransactionValue, universal_id::UniversalId,
    user::User,
};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signature};
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, collections::HashMap, fs::File, io::prelude::*, path::PathBuf};

pub struct Transaction {
    uid: UniversalId,
    pub from_pk: PublicKey,
    pub to_pk: PublicKey,
    pub value: TransactionValue,
}

impl Transaction {
    pub fn new(
        uid: UniversalId,
        from_pk: PublicKey,
        to_pk: PublicKey,
        value: TransactionValue,
    ) -> Transaction {
        Transaction {
            uid,
            from_pk,
            to_pk,
            value,
        }
    }
}

impl Serialize for Transaction {
    fn from_serialized(
        data: &[u8],
        mut i: &mut usize,
        users: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<Self>, String> {
        let universal_id = *UniversalId::from_serialized(&data, &mut i, users)?;
        let from_pk = *PublicKey::from_serialized(&data, i, users)?;
        let to_pk = *PublicKey::from_serialized(&data, i, users)?;
        let value = *TransactionValue::from_serialized(&data, i, users)?;
        users.entry(from_pk).or_insert_with(|| User::new(from_pk));
        let from_user = users.get_mut(&from_pk).unwrap();
        from_user.take(value)?;
        users.entry(to_pk).or_insert_with(|| User::new(to_pk));
        let to_user = users.get_mut(&to_pk).unwrap();
        to_user.give(value)?;
        Ok(Box::new(Transaction::new(
            universal_id,
            from_pk,
            to_pk,
            value,
        )))
    }

    fn serialize_into(&self, mut buffer: &mut [u8], mut i: &mut usize) -> Result<usize, String> {
        let start_i = *i;
        self.uid.serialize_into(&mut buffer, i)?;
        self.from_pk.serialize_into(&mut buffer, &mut i)?;
        self.to_pk.serialize_into(&mut buffer, &mut i)?;
        self.value.serialize_into(&mut buffer, &mut i)?;
        Ok(*i - start_i)
    }

    fn serialized_len(&self) -> Result<usize, String> {
        let transaction_len = self.uid.serialized_len()?
            + self.from_pk.serialized_len()?
            + self.to_pk.serialized_len()?
            + self.value.serialized_len()?;
        Ok(transaction_len)
    }
}

pub struct TransactionBlock {
    pub transactions: Vec<Transaction>,
    pub expected_signatures: usize,
    pub signatures: Vec<Signature>,
}

impl TransactionBlock {
    pub fn new(transactions: Vec<Transaction>, expected_signatures: usize) -> TransactionBlock {
        TransactionBlock {
            transactions,
            expected_signatures,
            signatures: Vec::new(),
        }
    }

    pub fn get_user_value_change(&mut self, pk: &mut PublicKey) -> Result<i32, String> {
        let mut tmp_value = 0;
        for transaction in self.transactions.iter_mut() {
            if transaction.value.is_coin_transfer()? {
                let transaction_value = transaction.value.get_value()? as i32;
                if pk == &mut transaction.from_pk {
                    tmp_value -= transaction_value;
                }
                if pk == &mut transaction.to_pk {
                    tmp_value += transaction_value;
                }
            }
        }
        Ok(tmp_value)
    }

    // pub fn len(&self) -> usize {
    //     self.transactions.len() * 188 + self.signatures.len() * 72
    // }

    pub fn sign(&mut self, sk: SecretKey) {
        let secp = Secp256k1::new();
        let bytes = &self.serialize_content().unwrap();
        let message = Message::from_slice(Sha256::digest(bytes).as_slice()).unwrap();
        self.signatures.push(secp.sign(&message, &sk));
    }

    pub fn sign_with_file(&mut self, sk_file_location: PathBuf) {
        let mut f = File::open(sk_file_location).unwrap();
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer).unwrap();
        let mut i = 0;
        let sk =
            *SecretKey::from_serialized(buffer.as_slice(), &mut i, &mut HashMap::new()).unwrap();
        self.sign(sk);
    }

    fn serialize_content(&mut self) -> Result<Vec<u8>, String> {
        if !self.transactions.is_empty() {
            let mut return_buffer =
                vec![0; self.transactions.len() * self.transactions[0].serialized_len()?];
            let mut i = 0;
            for transaction in self.transactions.iter_mut() {
                transaction.serialize_into(&mut return_buffer, &mut i)?;
            }
            return Ok(return_buffer);
        }
        Ok(Vec::new())
    }

    fn total_fee(&self) -> usize {
        let mut total_fee = 0;
        for transaction in self.transactions.iter() {
            if transaction.value.is_coin_transfer().is_ok()
                && transaction.value.is_coin_transfer().unwrap()
            {
                if let Ok(ref fee) = transaction.value.get_fee() {
                    total_fee += *fee as usize;
                }
            }
        }
        total_fee
    }
}

impl Ord for TransactionBlock {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.total_fee().cmp(&other.total_fee())
    }
}

impl Eq for TransactionBlock {
    fn assert_receiver_is_total_eq(&self) {}
}

impl PartialOrd for TransactionBlock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TransactionBlock {
    fn eq(&self, other: &Self) -> bool {
        self.total_fee() == other.total_fee()
    }
}

impl Serialize for TransactionBlock {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        mut users: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<TransactionBlock>, String> {
        let mut transactions = Vec::new();
        let mut seen_pks = Vec::new();
        loop {
            let transaction = *Transaction::from_serialized(&data, i, &mut users)?;
            let from_pk = transaction.from_pk;
            transactions.push(transaction);
            if !seen_pks.contains(&from_pk) {
                seen_pks.push(from_pk);
            }
            if !transactions.last().unwrap().uid.is_continuation() {
                break;
            }
        }
        let mut tmp_signatures: Vec<Signature> = Vec::new();
        for _ in seen_pks.iter() {
            match Signature::from_compact(&data[*i..*i + 64].to_vec()) {
                Ok(signature) => {
                    tmp_signatures.push(signature);
                    *i += signature.serialize_compact().len();
                }
                Err(e) => {
                    return Err(format!(
                        "Could not deserialize signatrue: {}",
                        e.to_string()
                    ))
                }
            }
        }
        Ok(Box::new(TransactionBlock {
            transactions,
            expected_signatures: seen_pks.len(),
            signatures: tmp_signatures,
        }))
    }

    fn serialize_into(&self, buffer: &mut [u8], i: &mut usize) -> Result<usize, String> {
        if self.expected_signatures != self.signatures.len() {
            return Err(format!(
                "Wrong amount of signatures; expected {} got {}",
                self.expected_signatures,
                self.signatures.len()
            ));
        }
        let content_start = *i;
        let mut seen_pks: Vec<PublicKey> = Vec::new();
        for transaction in self.transactions.iter() {
            transaction.serialize_into(buffer, i)?;
            if !seen_pks.contains(&transaction.from_pk) {
                seen_pks.push(transaction.from_pk);
            }
        }
        let content_end = *i;
        if seen_pks.len() != self.signatures.len() {
            return Err(format!(
                "Wrong amount of signatures on transaction, expected {} got {}",
                seen_pks.len(),
                self.signatures.len()
            ));
        }
        match Message::from_slice(Sha256::digest(&buffer[content_start..content_end]).as_slice()) {
            Ok(message) => {
                for (j, signature) in self.signatures.iter().enumerate() {
                    let secp = Secp256k1::new();
                    if secp
                        .verify(&message, &signature, &self.transactions[j].from_pk)
                        .is_err()
                    {
                        return Err(format!(
                            "Signature not valid for {}",
                            self.transactions[j].uid
                        ));
                    }
                    let vec_sig = signature.serialize_compact();
                    buffer[*i..*i + vec_sig.len()].copy_from_slice(&vec_sig);
                    *i += vec_sig.len();
                }
            }
            Err(e) => return Err(format!("Could not generate message from bytes: {}", e)),
        }
        Ok(*i - content_start)
    }

    fn serialized_len(&self) -> Result<usize, String> {
        let mut tmp_len = 0;
        for transaction in &self.transactions {
            tmp_len += transaction.serialized_len()?;
        }
        for signature in self.signatures.iter() {
            tmp_len += signature.serialize_compact().len();
        }
        Ok(tmp_len)
    }
}

impl AsRef<[u8]> for TransactionBlock {
    fn as_ref(&self) -> &[u8] {
        let out = vec![0; self.serialized_len().unwrap()];
        self.serialize_into(&mut out, &mut 0);
        out.as_slice()
    }
}
