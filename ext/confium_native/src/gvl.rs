//! GVL release for long blocking calls.
//!
//! magnus 0.8 does not wrap `rb_thread_call_without_gvl`, so the OTS
//! calendar round trip (up to 30s) would hold the GVL and freeze the
//! entire Ruby VM — including any Ruby thread serving as the peer.
//! This is the standard MRI mechanism: release the GVL for the
//! duration of a blocking FFI call, reacquire before touching Ruby
//! objects again. The closure must not touch the Ruby API.

use std::ffi::c_void;

unsafe extern "C" {
    fn rb_thread_call_without_gvl(
        func: extern "C" fn(*mut c_void) -> *mut c_void,
        data1: *mut c_void,
        ubf: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
        data2: *mut c_void,
    ) -> *mut c_void;
}

struct CallBox<F: FnOnce() -> T, T> {
    func: Option<F>,
    out: Option<T>,
}

extern "C" fn trampoline<F: FnOnce() -> T, T>(data: *mut c_void) -> *mut c_void {
    // SAFETY: data points at the CallBox constructed by without_gvl,
    // live for the duration of the call, on this same thread.
    let box_ = unsafe { &mut *(data as *mut CallBox<F, T>) };
    let func = box_.func.take().expect("trampoline runs once");
    box_.out = Some(func());
    std::ptr::null_mut()
}

/// Run `func` with the GVL released. Reacquires before returning.
///
/// # Safety (caller obligations)
///
/// `func` must not call the Ruby C API (no Ruby objects) and must be
/// callable from this thread while the GVL is released.
pub unsafe fn without_gvl<F: FnOnce() -> T, T>(func: F) -> T {
    let mut call = CallBox {
        func: Some(func),
        out: None,
    };
    // SAFETY: the trampoline and box are used per the contract above.
    unsafe {
        rb_thread_call_without_gvl(
            trampoline::<F, T>,
            &mut call as *mut CallBox<F, T> as *mut c_void,
            None,
            std::ptr::null_mut(),
        );
    }
    call.out.take().expect("trampoline stored the result")
}
