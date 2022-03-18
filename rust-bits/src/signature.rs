use std::io::Read;

use blake3;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_TABLE, ristretto::CompressedRistretto};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

fn scalar_from_reader(mut reader: blake3::OutputReader) -> Scalar {
    let mut digest = [0; 64];
    reader.read_exact(&mut digest).unwrap();
    Scalar::from_bytes_mod_order_wide(&digest)
}

/// The number of bytes in a private key.
pub const PRIVATE_KEY_SIZE: usize = 32;
/// The number of bytes in a public key.
pub const PUBLIC_KEY_SIZE: usize = 32;
/// The number of bytes in a signature.
pub const SIGNATURE_SIZE: usize = 64;

/// PrivateKey represents the key used for generating signatures.
///
/// This key should not be shared with anyone else. Doing so will allow them
/// to create signatures with this key.
#[derive(Clone)]
pub struct PrivateKey {
    /// bytes holds the raw data of our private key.
    ///
    /// Instead of a scalar, our private key presents a raw seed which can be used
    /// to derive other elements as needed for signing.
    bytes: [u8; PRIVATE_KEY_SIZE],
}

// We use different contexts to disambiguate different instance of key derivation.
const DERIVE_HASHING_KEY_CONTEXT: &'static str = "toy-coin 2021-11-11 derive hashing key";
const DERIVE_SCALAR_CONTEXT: &'static str = "toy-coin 2021-11-11 derive scalar";

impl PrivateKey {
    /// derive the private scalar associated with this seed.
    fn derive_scalar(&self) -> Scalar {
        scalar_from_reader(
            blake3::Hasher::new_derive_key(DERIVE_SCALAR_CONTEXT)
                .update(&self.bytes)
                .finalize_xof(),
        )
    }

    /// Read a private key from a raw pointer.
    ///
    /// For this to be safe, there needs to be at least PRIVATE_KEY_SIZE bytes
    /// worth of data at this address.
    ///
    /// This is purely a convenience method for FFI.
    pub unsafe fn from_pointer(data: *const u8) -> Self {
        let mut bytes: [u8; PRIVATE_KEY_SIZE] = [0; PRIVATE_KEY_SIZE];
        data.copy_to(bytes.as_mut_ptr(), PRIVATE_KEY_SIZE);
        PrivateKey { bytes }
    }

    /// create a new PrivateKey from randomness.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key = PrivateKey {
            bytes: [0; PRIVATE_KEY_SIZE],
        };
        rng.fill_bytes(&mut key.bytes);
        key
    }

    /// create a signature over a given message.
    ///
    /// This signature can be independently verified by anyone with the public key.
    /// The signature will fail to verify with a different public key, or with a different message.
    ///
    /// Randomness is passed for hedged signatures. This provides additional security
    /// against fault attacks, compared to plain deterministic signatures.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let private_scalar = self.derive_scalar();
        let public_point_compressed = (&private_scalar * &RISTRETTO_BASEPOINT_TABLE).compress();

        let hashing_key: [u8; blake3::KEY_LEN] =
            blake3::derive_key(DERIVE_HASHING_KEY_CONTEXT, &self.bytes);
        let surprise = scalar_from_reader(
            blake3::Hasher::new_keyed(&hashing_key)
                .update(message)
                .finalize_xof(),
        );
        let surprise_point_compressed = (&surprise * &RISTRETTO_BASEPOINT_TABLE).compress();

        let challenge = scalar_from_reader(
            blake3::Hasher::new()
                .update(public_point_compressed.as_bytes())
                .update(surprise_point_compressed.as_bytes())
                .update(message)
                .finalize_xof(),
        );

        let response = surprise + challenge * private_scalar;

        let mut signature = Signature([0; 64]);
        signature.0[..32].clone_from_slice(surprise_point_compressed.as_bytes());
        signature.0[32..].clone_from_slice(response.as_bytes());

        signature
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(&self.derive_scalar() * &RISTRETTO_BASEPOINT_TABLE)
    }
}

impl Into<[u8; PRIVATE_KEY_SIZE]> for PrivateKey {
    fn into(self) -> [u8; PRIVATE_KEY_SIZE] {
        self.bytes
    }
}

impl From<[u8; PRIVATE_KEY_SIZE]> for PrivateKey {
    fn from(bytes: [u8; PRIVATE_KEY_SIZE]) -> Self {
        Self { bytes }
    }
}

pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    /// Read a signature from a raw pointer.
    ///
    /// For this to be safe, there needs to be at least SIGNATURE_SIZE bytes
    /// worth of data at this address.
    ///
    /// This is purely a convenience method for FFI.
    pub unsafe fn from_pointer(data: *const u8) -> Self {
        let mut sig_bytes: [u8; SIGNATURE_SIZE] = [0; SIGNATURE_SIZE];
        data.copy_to(sig_bytes.as_mut_ptr(), SIGNATURE_SIZE);
        Signature(sig_bytes)
    }
}

impl Into<[u8; SIGNATURE_SIZE]> for Signature {
    fn into(self) -> [u8; SIGNATURE_SIZE] {
        self.0
    }
}

impl From<[u8; SIGNATURE_SIZE]> for Signature {
    fn from(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Signature(bytes)
    }
}

pub struct PublicKey(RistrettoPoint);

impl PublicKey {
    pub fn verify(&self, signature: &Signature, message: &[u8]) -> bool {
        let surprise_point_compressed = CompressedRistretto::from_slice(&signature.0[..32]);
        let response = match Scalar::from_canonical_bytes(signature.0[32..].try_into().unwrap()) {
            Some(x) => x,
            None => return false,
        };

        let challenge = scalar_from_reader(
            blake3::Hasher::new()
                .update(self.0.compress().as_bytes())
                .update(surprise_point_compressed.as_bytes())
                .update(message)
                .finalize_xof(),
        );

        let should_be_surprise_point =
            RistrettoPoint::vartime_double_scalar_mul_basepoint(&-challenge, &self.0, &response);

        bool::from(
            should_be_surprise_point
                .compress()
                .ct_eq(&surprise_point_compressed),
        )
    }
}

impl<'a> Into<[u8; PUBLIC_KEY_SIZE]> for &'a PublicKey {
    fn into(self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0.compress().to_bytes()
    }
}

impl<'a> TryFrom<&'a [u8]> for PublicKey {
    type Error = ();

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() != PUBLIC_KEY_SIZE {
            return Err(());
        }
        let compressed = CompressedRistretto::from_slice(value);
        let decompressed = compressed.decompress().ok_or(())?;
        if decompressed.is_identity() {
            return Err(());
        }
        Ok(Self(decompressed))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_signing_message_verifies() {
        let message = b"hello world";
        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = private_key.public_key();
        let signature = private_key.sign(message);
        assert!(public_key.verify(&signature, message));
    }

    #[test]
    fn test_signing_message_does_not_verify_with_different_message() {
        let message1 = b"hello world";
        let message2 = b"bonjour monde";
        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = private_key.public_key();
        let signature = private_key.sign(message1);
        assert!(!public_key.verify(&signature, message2));
    }

    #[test]
    fn test_signing_message_does_not_verify_with_different_key() {
        let message = b"hello world";
        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = PrivateKey::random(&mut OsRng).public_key();
        let signature = private_key.sign(message);
        assert!(!public_key.verify(&signature, message));
    }
}
