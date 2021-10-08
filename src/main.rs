extern crate chrono;
extern crate ed25519_dalek;
extern crate generic_array;
extern crate sha3;

mod signature;

//use crate::signature::{PublicKey, SecretKey, Signature};
use chrono::{DateTime, Utc};
use ed25519_dalek::{PublicKey, Signature};
use generic_array::typenum::{U16, U32, U8};
use generic_array::GenericArray;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

type HashOutput = GenericArray<u8, U32>;
type Proof = GenericArray<u8, U8>;
type Timestamp = DateTime<Utc>;
type Identity = GenericArray<u8, U16>;
type State = HashMap<Identity, (PublicKey, u128, u64)>; // maps public keys to public key, coin amount and counter
type KnownTimelines = HashMap<HashOutput, (Block, State, usize)>;

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

#[derive(Clone)]
struct Block {
    prev_hash: HashOutput, // Hash of the previous block
    proof: Proof, // Used by the proof of work algorithm to find a good partial preimage to the next block
    miner_pk: PublicKey, // The public key that gets the mining reward
    timestamp: Timestamp,
    actions: Vec<Action>, // List of transactions
}

impl Block {
    fn perform(self, timelines: &mut KnownTimelines) -> bool {
        match timelines.get(&self.prev_hash) {
            Some((prev_block, prev_state, prev_max_size)) => {
                if !(prev_block.timestamp < self.timestamp && self.timestamp < Utc::now()) {
                    return false;
                }
                let mut state = prev_state.clone();
                for action in &self.actions {
                    if !action.verify(&state) {
                        return false;
                    }
                    action.perform(&mut state);
                }
                let mut max_size = *prev_max_size;
                if prev_block.actions.len() == *prev_max_size {
                    max_size += 1;
                } else if prev_block.actions.len() < *prev_max_size / 2 {
                    max_size -= 1;
                }
                timelines.insert(hash(&self.to_bytes()), (self, state, max_size));
                // TODO Check PoW
                true
            }
            None => false,
        }
    }

    // TODO add timestamp in here
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for b in self
            .prev_hash
            .iter()
            .chain(&self.proof)
            .chain(&self.miner_pk.to_bytes())
        {
            result.push(*b)
        }
        for action in &self.actions {
            result.append(&mut action.to_bytes());
        }
        result
    }
}

#[derive(Clone)]
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
    // performs the action without checking anything
    fn perform(&self, state: &mut State) {
        match self {
            Action::AddPublicKey { id, pk } => {
                state.insert(*id, (*pk, 0, 0));
            }
            Action::Transaction {
                source,
                sink,
                counter: _,
                amount,
                signature: _,
            } => {
                state
                    .entry(*source)
                    .and_modify(|(_, source_amount, source_counter)| {
                        *source_amount -= amount;
                        *source_counter += 1;
                    });
                state.entry(*sink).and_modify(|(_, sink_amount, _)| {
                    *sink_amount += amount;
                });
            }
        }
    }

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

                    (*state_amount >= *amount)                  // verify enough coins for transaction
                        && (*state_counter + 1 == *counter)     // verify counting up correctly
                        && pk                                   // verify the signature
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

    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        match self {
            Action::Transaction {
                source,
                sink,
                counter,
                amount,
                signature,
            } => {
                result.push(0);
                for i in source
                    .iter()
                    .chain(sink.iter())
                    .chain(&counter.to_be_bytes())
                    .chain(&amount.to_be_bytes())
                    .chain(&signature.to_bytes())
                {
                    result.push(*i);
                }
            }
            Action::AddPublicKey { id, pk } => {
                result.push(1);
                for i in id.iter().chain(&pk.to_bytes()) {
                    result.push(*i);
                }
            }
        };
        result
    }
}
