use crate::{
    merkle_forest::HASH_SIZE,
    serialize::{DynamicSized, Serialize},
    transaction_input::TransactionInput,
    transaction_output::TransactionOutput,
    transaction_varuint::TransactionVarUint,
    transaction_version::TransactionVersion,
    user::User,
};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Clone)]
pub struct Transaction {
    version: TransactionVersion,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
}

impl Transaction {
    pub fn new(
        version: TransactionVersion,
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
    ) -> Self {
        Transaction {
            version,
            inputs,
            outputs,
        }
    }

    pub fn get_output(&self, index: &TransactionVarUint) -> TransactionOutput {
        self.outputs[index.get_value()].clone()
    }

    pub fn hash(&self) -> Result<[u8; 32], String> {
        let mut data = vec![0; self.serialized_len()];
        self.serialize_into(&mut data, &mut 0)?;
        let mut hash = [0; 32];
        hash.copy_from_slice(&Sha256::digest(&data));
        Ok(hash)
    }

    pub fn get_total_fee(&self) -> u128 {
        let mut total_fee = 0;
        for output in self.outputs.iter() {
            if output.value.is_coin_transfer() {
                total_fee += output.value.get_fee().unwrap();
            }
        }
        total_fee
    }

    // pub fn get_total_value(&self) -> u128 {
    //     let mut total_value = 0;
    //     for output in self.outputs.iter() {
    //         if output.value.is_coin_transfer() {
    //             total_fee += output.value.get_fee().unwrap();
    //         }
    //     }
    //     total_fee
    // }

    fn get_sign_hash(&self) -> [u8; HASH_SIZE] {
        let mut digest = vec![0u8; HASH_SIZE * (1 + self.outputs.len() + self.inputs.len())];
        let mut i = 0;
        digest[i..i + HASH_SIZE].copy_from_slice(&self.version.hash());
        i += HASH_SIZE;
        for input in self.inputs.iter() {
            digest[i..i + HASH_SIZE].copy_from_slice(&input.sign_hash());
            i += HASH_SIZE;
        }
        for output in self.outputs.iter() {
            digest[i..i + HASH_SIZE].copy_from_slice(&output.hash());
            i += HASH_SIZE;
        }
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&Sha256::digest(&digest));
        hash
    }

    pub fn sign(&mut self, sk: SecretKey, index: usize) -> Result<bool, String> {
        let last_index = self.inputs.len() - 1;
        if index > last_index {
            return Err(format!(
                "Index out of range, expected max {} got {}",
                last_index, index
            ));
        }
        match self.inputs[index].signature {
            Some(_) => Err(format!("Input at index {} already signed", index)),
            None => {
                let secp = Secp256k1::new();
                let message =
                    Message::from_slice(Sha256::digest(&self.get_sign_hash()).as_slice()).unwrap();
                self.inputs[index].signature = Some(secp.sign(&message, &sk));
                Ok(true)
            }
        }
    }
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Serialize for Transaction {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        users: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<Self>, String> {
        let version = *TransactionVersion::from_serialized(&data, i, users)?;
        let num_of_inputs = (*TransactionVarUint::from_serialized(&data, i, users)?).get_value();
        let mut inputs = Vec::new();
        for _ in 0..num_of_inputs {
            inputs.push(*TransactionInput::from_serialized(&data, i, users)?);
        }
        let num_of_outputs = (*TransactionVarUint::from_serialized(&data, i, users)?).get_value();
        let mut outputs = Vec::new();
        for _ in 0..num_of_outputs {
            outputs.push(*TransactionOutput::from_serialized(&data, i, users)?);
        }
        Ok(Box::new(Transaction {
            version,
            inputs,
            outputs,
        }))
    }

    fn serialize_into(&self, mut buffer: &mut [u8], i: &mut usize) -> Result<usize, String> {
        let start_i = *i;
        self.version.serialize_into(&mut buffer, i)?;
        TransactionVarUint::from_usize(self.inputs.len()).serialize_into(&mut buffer, i)?;
        for input in self.inputs.iter() {
            input.serialize_into(&mut buffer, i)?;
        }
        TransactionVarUint::from_usize(self.outputs.len()).serialize_into(&mut buffer, i)?;
        for output in self.outputs.iter() {
            output.serialize_into(&mut buffer, i)?;
        }
        Ok(*i - start_i)
    }
}

impl DynamicSized for Transaction {
    fn serialized_len(&self) -> usize {
        self.version.serialized_len()
            + TransactionVarUint::from_usize(self.inputs.len()).serialized_len()
            + TransactionVarUint::from_usize(self.outputs.len()).serialized_len()
            + self
                .inputs
                .iter()
                .fold(0usize, |sum, val| sum + val.serialized_len())
            + self
                .outputs
                .iter()
                .fold(0usize, |sum, val| sum + val.serialized_len())
    }
}

// pub struct TransactionBlock {
//     pub transactions: Vec<Transaction>,
//     pub expected_signatures: usize,
//     pub signatures: Vec<Signature>,
// }

// impl TransactionBlock {
//     pub fn new(transactions: Vec<Transaction>, expected_signatures: usize) -> TransactionBlock {
//         TransactionBlock {
//             transactions,
//             expected_signatures,
//             signatures: Vec::new(),
//         }
//     }

//     pub fn get_user_value_change(&mut self, pk: &mut PublicKey) -> Result<i32, String> {
//         let mut tmp_value = 0;
//         for transaction in self.transactions.iter_mut() {
//             if transaction.value.is_coin_transfer() {
//                 let transaction_value = transaction.value.get_value()? as i32;
//                 if pk == &mut transaction.from_pk {
//                     tmp_value -= transaction_value;
//                 }
//                 if pk == &mut transaction.to_pk {
//                     tmp_value += transaction_value;
//                 }
//             }
//         }
//         Ok(tmp_value)
//     }

//     pub fn hash(&self) -> Result<[u8; 32], String> {
//         let mut data = vec![0; self.serialized_len()];
//         self.serialize_into(&mut data, &mut 0)?;
//         let mut hash = [0; 32];
//         hash.copy_from_slice(&Sha256::digest(&data));
//         Ok(hash)
//     }

//     // pub fn len(&self) -> usize {
//     //     self.transactions.len() * 188 + self.signatures.len() * 72
//     // }

//     pub fn sign(&mut self, sk: SecretKey) {
//         let secp = Secp256k1::new();
//         let bytes = &self.serialize_content().unwrap();
//         let message = Message::from_slice(Sha256::digest(bytes).as_slice()).unwrap();
//         self.signatures.push(secp.sign(&message, &sk));
//     }

//     pub fn sign_with_file(&mut self, sk_file_location: PathBuf) {
//         let mut f = File::open(sk_file_location).unwrap();
//         let mut buffer = Vec::new();
//         f.read_to_end(&mut buffer).unwrap();
//         let mut i = 0;
//         let sk =
//             *SecretKey::from_serialized(buffer.as_slice(), &mut i, &mut HashMap::new()).unwrap();
//         self.sign(sk);
//     }

//     fn serialize_content(&mut self) -> Result<Vec<u8>, String> {
//         if !self.transactions.is_empty() {
//             let mut return_buffer =
//                 vec![0; self.transactions.len() * Transaction::serialized_len()];
//             let mut i = 0;
//             for transaction in self.transactions.iter_mut() {
//                 transaction.serialize_into(&mut return_buffer, &mut i)?;
//             }
//             return Ok(return_buffer);
//         }
//         Ok(Vec::new())
//     }

//     fn total_fee(&self) -> usize {
//         let mut total_fee = 0;
//         for transaction in self.transactions.iter() {
//             if transaction.value.is_coin_transfer() {
//                 if let Ok(ref fee) = transaction.value.get_fee() {
//                     total_fee += *fee as usize;
//                 }
//             }
//         }
//         total_fee
//     }
// }

// impl Ord for TransactionBlock {
//     fn cmp(&self, other: &Self) -> std::cmp::Ordering {
//         self.total_fee().cmp(&other.total_fee())
//     }
// }

// impl Eq for TransactionBlock {
//     fn assert_receiver_is_total_eq(&self) {}
// }

// impl PartialOrd for TransactionBlock {
//     fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
//         Some(self.cmp(other))
//     }
// }

// impl PartialEq for TransactionBlock {
//     fn eq(&self, other: &Self) -> bool {
//         self.total_fee() == other.total_fee()
//     }
// }

// impl Serialize for TransactionBlock {
//     fn from_serialized(
//         data: &[u8],
//         i: &mut usize,
//         mut users: &mut HashMap<PublicKey, User>,
//     ) -> Result<Box<TransactionBlock>, String> {
//         let mut transactions = Vec::new();
//         let mut seen_pks = Vec::new();
//         loop {
//             let transaction = *Transaction::from_serialized(&data, i, &mut users)?;
//             let from_pk = transaction.from_pk;
//             transactions.push(transaction);
//             if !seen_pks.contains(&from_pk) {
//                 seen_pks.push(from_pk);
//             }
//             if !transactions.last().unwrap().uid.is_continuation() {
//                 break;
//             }
//         }
//         let mut tmp_signatures: Vec<Signature> = Vec::new();
//         for _ in seen_pks.iter() {
//             match Signature::from_compact(&data[*i..*i + 64].to_vec()) {
//                 Ok(signature) => {
//                     tmp_signatures.push(signature);
//                     *i += signature.serialize_compact().len();
//                 }
//                 Err(e) => {
//                     return Err(format!(
//                         "Could not deserialize signatrue: {}",
//                         e.to_string()
//                     ))
//                 }
//             }
//         }
//         Ok(Box::new(TransactionBlock {
//             transactions,
//             expected_signatures: seen_pks.len(),
//             signatures: tmp_signatures,
//         }))
//     }

//     fn serialize_into(&self, buffer: &mut [u8], i: &mut usize) -> Result<usize, String> {
//         if self.expected_signatures != self.signatures.len() {
//             return Err(format!(
//                 "Wrong amount of signatures; expected {} got {}",
//                 self.expected_signatures,
//                 self.signatures.len()
//             ));
//         }
//         let content_start = *i;
//         let mut seen_pks: Vec<PublicKey> = Vec::new();
//         for transaction in self.transactions.iter() {
//             transaction.serialize_into(buffer, i)?;
//             if !seen_pks.contains(&transaction.from_pk) {
//                 seen_pks.push(transaction.from_pk);
//             }
//         }
//         let content_end = *i;
//         if seen_pks.len() != self.signatures.len() {
//             return Err(format!(
//                 "Wrong amount of signatures on transaction, expected {} got {}",
//                 seen_pks.len(),
//                 self.signatures.len()
//             ));
//         }
//         match Message::from_slice(Sha256::digest(&buffer[content_start..content_end]).as_slice()) {
//             Ok(message) => {
//                 for (j, signature) in self.signatures.iter().enumerate() {
//                     let secp = Secp256k1::new();
//                     if secp
//                         .verify(&message, &signature, &self.transactions[j].from_pk)
//                         .is_err()
//                     {
//                         return Err(format!(
//                             "Signature not valid for {}",
//                             self.transactions[j].uid
//                         ));
//                     }
//                     let vec_sig = signature.serialize_compact();
//                     buffer[*i..*i + vec_sig.len()].copy_from_slice(&vec_sig);
//                     *i += vec_sig.len();
//                 }
//             }
//             Err(e) => return Err(format!("Could not generate message from bytes: {}", e)),
//         }
//         Ok(*i - content_start)
//     }
// }
// impl DynamicSized for TransactionBlock {
//     fn serialized_len(&self) -> usize {
//         let mut tmp_len = Transaction::serialized_len() * self.transactions.len();
//         for signature in self.signatures.iter() {
//             tmp_len += signature.serialize_compact().len();
//         }
//         tmp_len
//     }
// }

// impl AsRef<[u8]> for TransactionBlock {
//     fn as_ref(&self) -> &[u8] {
//         let mut out = vec![0; self.serialized_len()];
//         self.serialize_into(&mut out, &mut 0);
//         out.as_slice()
//     }
// }
