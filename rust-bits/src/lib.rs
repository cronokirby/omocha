extern crate curve25519_dalek;

mod signature;

#[no_mangle]
pub extern "C" fn double(x: i32) -> i32 {
    2 * x
}

const S: &'static [u8] = b"hello";

#[no_mangle]
pub extern "C" fn init(out: *mut u8) {
    unsafe { out.copy_from(S.as_ptr(), S.len()) }
}
