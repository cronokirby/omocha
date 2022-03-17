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
