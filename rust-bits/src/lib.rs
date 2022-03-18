mod proof_of_work;
mod signature;

use rand_core::OsRng;
use std::slice;

#[no_mangle]
pub extern "C" fn signature_generate_private_key(out: *mut u8) {
    let private_bytes: [u8; signature::PRIVATE_KEY_SIZE] =
        signature::PrivateKey::random(&mut OsRng).into();
    let slice = &private_bytes;
    unsafe { out.copy_from(slice.as_ptr(), slice.len()) }
}

#[no_mangle]
pub extern "C" fn signature_private_key_to_public_key(
    private_ptr: *const u8,
) -> Box<signature::PublicKey> {
    Box::new(unsafe { signature::PrivateKey::from_pointer(private_ptr) }.public_key())
}

#[no_mangle]
pub extern "C" fn signature_free_public_key(_: Box<signature::PublicKey>) {}

#[no_mangle]
pub extern "C" fn signature_public_key_compress(pk: &signature::PublicKey, out: *mut u8) {
    let pk_bytes: [u8; signature::PUBLIC_KEY_SIZE] = pk.into();
    unsafe { out.copy_from(pk_bytes.as_ptr(), pk_bytes.len()) }
}

#[no_mangle]
pub extern "C" fn signature_public_key_decompress(
    data: *const u8,
    data_len: usize,
) -> Option<Box<signature::PublicKey>> {
    let data = unsafe { slice::from_raw_parts(data, data_len) };
    match signature::PublicKey::try_from(data) {
        Err(_) => None,
        Ok(pk) => Some(Box::new(pk)),
    }
}

#[no_mangle]
pub extern "C" fn signature_sign(
    priv_ptr: *const u8,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) {
    let private = unsafe { signature::PrivateKey::from_pointer(priv_ptr) };
    let message = unsafe { slice::from_raw_parts(data, data_len) };
    let sig_bytes: [u8; signature::SIGNATURE_SIZE] = private.sign(message).into();
    unsafe { out.copy_from(sig_bytes.as_ptr(), sig_bytes.len()) }
}

#[no_mangle]
pub extern "C" fn signature_verify(
    public: &signature::PublicKey,
    data: *const u8,
    data_len: usize,
    sig_ptr: *const u8,
) -> bool {
    let message = unsafe { slice::from_raw_parts(data, data_len) };
    let sig = unsafe { signature::Signature::from_pointer(sig_ptr) };
    public.verify(&sig, message)
}

#[no_mangle]
pub extern "C" fn proof_of_work_check(data: *const u8, data_len: usize, proof: *const u8) -> bool {
    let context = unsafe { slice::from_raw_parts(data, data_len) };
    let mut pow_bytes = [0; proof_of_work::PROOF_OF_WORK_SIZE];
    unsafe { proof.copy_to(pow_bytes.as_mut_ptr(), proof_of_work::PROOF_OF_WORK_SIZE) };
    let pow = proof_of_work::ProofOfWork::from(pow_bytes);
    pow.check(context)
}

#[no_mangle]
pub extern "C" fn proof_of_work_try(
    data: *const u8,
    data_len: usize,
    tries: usize,
    out: *mut u8,
) -> bool {
    let context = unsafe { slice::from_raw_parts(data, data_len) };
    match proof_of_work::ProofOfWork::try_many(
        &mut OsRng,
        context,
        proof_of_work::DEFAULT_DIFFICULTY,
        tries,
    ) {
        None => false,
        Some(pow) => {
            let pow_bytes: [u8; proof_of_work::PROOF_OF_WORK_SIZE] = pow.into();
            unsafe { out.copy_from(pow_bytes.as_ptr(), proof_of_work::PROOF_OF_WORK_SIZE) };
            true
        }
    }
}

#[no_mangle]
pub extern "C" fn proof_of_work_make(data: *const u8, data_len: usize, out: *mut u8) {
    let context = unsafe { slice::from_raw_parts(data, data_len) };
    let pow = proof_of_work::ProofOfWork::try_forever(
        &mut OsRng,
        context,
        proof_of_work::DEFAULT_DIFFICULTY,
    );
    let pow_bytes: [u8; proof_of_work::PROOF_OF_WORK_SIZE] = pow.into();
    unsafe { out.copy_from(pow_bytes.as_ptr(), proof_of_work::PROOF_OF_WORK_SIZE) };
}
