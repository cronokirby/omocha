use rand_core::{CryptoRng, RngCore};

use argon2;

const HASH_SIZE: usize = 16;
const NONCE_SIZE: usize = 32;

/// The number of bytes in a proof of work.
///
/// We have 32 bytes for the nonce, and 32 bytes for the hash.
/// The rationale behind using 32 bytes for the nonce is to be able to easily
/// select nonces at random without worrying about colliding with other
/// miners.
pub const PROOF_OF_WORK_SIZE: usize = NONCE_SIZE + HASH_SIZE;

/// DEFAULT_DIFFICULTY restricts the space of valid hashes.
///
/// If the difficulty is D, the hash must be >= D. D directly represents
/// the number of invalid hashes.
pub const DEFAULT_DIFFICULTY: u128 = 0;

fn default_config() -> argon2::Config<'static> {
    argon2::Config {
        ad: b"Omocha v0.1.0 Proof of Work",
        hash_length: HASH_SIZE as u32,
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

fn hash_once(nonce: &[u8], msg: &[u8]) -> u128 {
    let hash = argon2::hash_raw(msg, nonce, &default_config()).expect("failed to run argon2 hash");
    u128::from_le_bytes(hash.try_into().unwrap())
}

/// Represents a proof that a certain amount of computation has been done.
///
/// This proof is bound to a given context, preventing it from being valid
/// outside of that context.
pub struct ProofOfWork {
    difficulty: u128,
    nonce: [u8; NONCE_SIZE],
    hash: u128,
}

impl ProofOfWork {
    /// check whether or not this proof of work is valid over a given context.
    pub fn check(&self, ctx: &[u8]) -> bool {
        self.hash >= self.difficulty && self.hash == hash_once(&self.nonce, ctx)
    }

    /// try to generate a valid proof of work once.
    pub fn try_once<R: RngCore + CryptoRng>(
        rng: &mut R,
        ctx: &[u8],
        difficulty: u128,
    ) -> Option<Self> {
        let mut nonce = [0; NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        let hash = hash_once(&nonce, ctx);
        if hash < difficulty {
            None
        } else {
            Some(Self {
                difficulty,
                nonce,
                hash,
            })
        }
    }

    /// try to generate a valid proof of work multiple times.
    pub fn try_many<R: RngCore + CryptoRng>(
        rng: &mut R,
        ctx: &[u8],
        difficulty: u128,
        tries: usize,
    ) -> Option<Self> {
        for _ in 0..tries {
            match Self::try_once(rng, ctx, difficulty) {
                Some(x) => return Some(x),
                None => {}
            }
        }
        None
    }

    /// generate a valid proof of work by iterating until one is found.
    pub fn try_forever<R: RngCore + CryptoRng>(rng: &mut R, ctx: &[u8], difficulty: u128) -> Self {
        loop {
            match Self::try_once(rng, ctx, difficulty) {
                Some(x) => return x,
                None => {}
            }
        }
    }
}

impl Into<[u8; PROOF_OF_WORK_SIZE]> for ProofOfWork {
    fn into(self) -> [u8; PROOF_OF_WORK_SIZE] {
        let mut out = [0; PROOF_OF_WORK_SIZE];
        out[..NONCE_SIZE].copy_from_slice(&self.nonce);
        out[NONCE_SIZE..].copy_from_slice(&self.hash.to_le_bytes());
        out
    }
}

impl From<[u8; PROOF_OF_WORK_SIZE]> for ProofOfWork {
    fn from(bytes: [u8; PROOF_OF_WORK_SIZE]) -> Self {
        let mut nonce = [0; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[..NONCE_SIZE]);
        let hash = u128::from_le_bytes((&bytes[NONCE_SIZE..]).try_into().unwrap());
        Self {
            difficulty: DEFAULT_DIFFICULTY,
            nonce,
            hash,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_proof_of_work_is_valid() {
        let ctx = b"context";
        let pow = ProofOfWork::try_forever(&mut OsRng, ctx, 0);
        assert!(pow.check(ctx));
    }

    #[test]
    fn test_proof_of_work_is_invalid_on_different_context() {
        let ctxa = b"contextA";
        let ctxb = b"contextB";
        let pow = ProofOfWork::try_forever(&mut OsRng, ctxa, 0);
        assert!(!pow.check(ctxb));
    }
}
