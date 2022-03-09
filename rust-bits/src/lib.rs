mod signature;
use rand_core::OsRng;
use signature::PRIVATE_KEY_SIZE;

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
    let mut private_bytes: [u8; PRIVATE_KEY_SIZE] = [0; PRIVATE_KEY_SIZE];
    unsafe { private_ptr.copy_to(private_bytes.as_mut_ptr(), PRIVATE_KEY_SIZE) }
    let private_key = signature::PrivateKey::from(private_bytes);
    Box::new(private_key.public_key())
}

#[no_mangle]
pub extern "C" fn signature_free_public_key(_: Box<signature::PublicKey>) {}

#[no_mangle]
pub extern "C" fn signature_public_key_compress(pk: &signature::PublicKey, out: *mut u8) {
    let pk_bytes: [u8; signature::PUBLIC_KEY_SIZE] = pk.into();
    let pk_slice = &pk_bytes;
    unsafe { out.copy_from(pk_slice.as_ptr(), pk_slice.len()) }
}
