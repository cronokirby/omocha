use std::hash::Hash;

use argon2;

const HASH_SIZE: usize = 32;
const NONCE_SIZE: usize = 32;

/// The number of bytes in a proof of work.
///
/// We have 32 bytes for the nonce, and 32 bytes for the hash.
/// The rationale behind using 32 bytes for the nonce is to be able to easily
/// select nonces at random without worrying about colliding with other
/// miners.
const PROOF_OF_WORK_SIZE: usize = NONCE_SIZE + HASH_SIZE;

fn default_config() -> argon2::Config<'static> {
    argon2::Config {
        ad: b"Omocha v0.1.0 Proof of Work",
        hash_length: 32,
        lanes: 1,
        mem_cost: 65536,
        secret: &[],
        thread_mode: argon2::ThreadMode::Sequential,
        // No point in having multiple iterations internally
        time_cost: 1,
        // We want the d variation, which has some GPU resistance.
        variant: argon2::Variant::Argon2d,
        version: argon2::Version::Version13,
    }
}

fn hash_once(nonce: &[u8], msg: &[u8]) -> Vec<u8> {
    argon2::hash_raw(msg, nonce, &default_config()).expect("failed to run argon2 hash")
}

pub struct ProofOfWork {
    bytes: [u8; PROOF_OF_WORK_SIZE],
}

impl ProofOfWork {
    /// check whether or not this proof of work is valid over a given context.
    pub fn check(&self, ctx: &[u8]) -> bool {
        let nonce = &self.bytes[..NONCE_SIZE];
        let hash = &self.bytes[NONCE_SIZE..];
        hash == hash_once(nonce, ctx).as_slice()
    }
}

impl Into<[u8; PROOF_OF_WORK_SIZE]> for ProofOfWork {
    fn into(self) -> [u8; PROOF_OF_WORK_SIZE] {
        self.bytes
    }
}

impl From<[u8; PROOF_OF_WORK_SIZE]> for ProofOfWork {
    fn from(bytes: [u8; PROOF_OF_WORK_SIZE]) -> Self {
        Self { bytes }
    }
}
