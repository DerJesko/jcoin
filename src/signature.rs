use std::hash::{Hash, Hasher};

#[derive(Eq)]
pub struct PublicKey(ed25519_dalek::PublicKey);

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

pub type SecretKey = ed25519_dalek::Keypair;

pub type Signature = ed25519_dalek::Signature;
