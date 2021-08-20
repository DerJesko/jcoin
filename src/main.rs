extern crate ed25519;
extern crate ed25519_dalek;
extern crate generic_array;
extern crate sha3;

mod signature;

//use crate::signature::{PublicKey, SecretKey, Signature};
use ed25519_dalek::{PublicKey, Signature};
use generic_array::typenum::{U16, U32, U8};
use generic_array::GenericArray;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

type HashOutput = GenericArray<u8, U32>;
type TestingSpace = GenericArray<u8, U8>;
type Timestamp = ();
type Identity = GenericArray<u8, U16>;
type State = HashMap<Identity, (PublicKey, u128, u64)>; // maps public keys to public key, coin amount and counter

fn hash(input: &[u8]) -> HashOutput {
    Sha3_256::digest(input)
}

fn main() {
    let result = Sha3_256::digest(b"my message");
    let mut v = Vec::new();
    for i in result {
        v.push(i);
    }
    println!("{:?}", v);
}

struct Block {
    prev_hash: HashOutput,       // Hash of the previous block
    testing_space: TestingSpace, // Used by the proof of work algorithm to find a good partial preimage to the next block
    miner_pk: PublicKey,         // The public key that gets the mining reward
    timestamp: Timestamp,
    actions: Vec<Action>, // List of transactions
}

impl Block {
    /*
    verify block:
    is the prev hash correct
    is timestamp in the past
    is timestamp in the future of the one before
    check transactions
    is block too big
    */
}

enum Action {
    Transaction {
        source: Identity,
        sink: Identity,
        counter: u64,
        amount: u128,
        signature: Signature,
    },
    AddPublicKey {
        id: Identity,
        pk: PublicKey,
    },
}
impl Action {
    /*
    verify transaction:
    verify signature ✓
    check if counter is >= counter in state ✓
    check if sink has enough coins ✓
    */
    fn verify(&self, state: &State) -> bool {
        match self {
            Action::Transaction {
                source,
                sink,
                counter,
                amount,
                signature,
            } => match state.get(source) {
                Some((pk, state_amount, state_counter)) => {
                    let mut to_sign_information = Vec::new();
                    for i in source
                        .iter()
                        .chain(sink.iter())
                        .chain(&counter.to_be_bytes())
                        .chain(&amount.to_be_bytes())
                    {
                        to_sign_information.push(*i);
                    }

                    (*state_amount >= *amount)
                        && (*state_counter <= *counter)
                        && pk
                            .verify_strict(&to_sign_information[..], &signature)
                            .is_ok()
                }
                None => false,
            },
            Action::AddPublicKey { id, pk: _ } => match state.get(id) {
                Some(_) => false,
                None => true,
            },
        }
    }
}
