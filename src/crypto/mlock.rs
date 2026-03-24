// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Memory locking utilities for key material protection.
//!
//! On Unix systems, uses mlock(2) to prevent key material from being
//! swapped to disk. On Windows, uses VirtualLock/VirtualUnlock for the
//! same purpose. Both prevent sensitive key material from being paged
//! to the swap file.

/// Lock a buffer into memory so it cannot be paged to swap.
/// Returns Ok(()) on success or if not supported on this platform.
#[cfg(unix)]
pub fn mlock_buffer(ptr: *const u8, len: usize) -> Result<(), std::io::Error> {
    if len == 0 || ptr.is_null() {
        return Ok(());
    }
    // Miri cannot execute FFI calls like mlock; treat as no-op.
    if cfg!(miri) {
        return Ok(());
    }
    // SAFETY: ptr and len describe a valid allocated region (caller guarantees).
    // mlock only advises the kernel; it does not modify the buffer.
    let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Unlock a previously mlocked buffer.
#[cfg(unix)]
pub fn munlock_buffer(ptr: *const u8, len: usize) -> Result<(), std::io::Error> {
    if len == 0 || ptr.is_null() {
        return Ok(());
    }
    // Miri cannot execute FFI calls like munlock; treat as no-op.
    if cfg!(miri) {
        return Ok(());
    }
    // SAFETY: ptr and len describe a valid allocated region (caller guarantees).
    let ret = unsafe { libc::munlock(ptr as *const libc::c_void, len) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Lock a buffer into physical memory using Windows VirtualLock.
/// Prevents the pages from being paged to the swap file.
///
/// Note: VirtualLock requires the process to have SE_LOCK_MEMORY_PAGES privilege
/// for large allocations, but small buffers (≤ working set minimum) succeed
/// without special privileges.
#[cfg(windows)]
pub fn mlock_buffer(ptr: *const u8, len: usize) -> Result<(), std::io::Error> {
    if len == 0 || ptr.is_null() {
        return Ok(());
    }
    // SAFETY: ptr and len describe a valid allocated region (caller guarantees).
    // VirtualLock locks the pages into physical memory; it does not modify
    // the buffer contents.
    let ret = unsafe {
        windows_sys::Win32::System::Memory::VirtualLock(ptr as *mut core::ffi::c_void, len)
    };
    if ret != 0 {
        Ok(()) // VirtualLock returns non-zero on success
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Unlock a previously VirtualLock-ed buffer on Windows.
#[cfg(windows)]
pub fn munlock_buffer(ptr: *const u8, len: usize) -> Result<(), std::io::Error> {
    if len == 0 || ptr.is_null() {
        return Ok(());
    }
    // SAFETY: ptr and len describe a valid allocated region (caller guarantees).
    let ret = unsafe {
        windows_sys::Win32::System::Memory::VirtualUnlock(ptr as *mut core::ffi::c_void, len)
    };
    if ret != 0 {
        Ok(()) // VirtualUnlock returns non-zero on success
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlock_empty_buffer() {
        assert!(mlock_buffer(std::ptr::null(), 0).is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_mlock_munlock_roundtrip() {
        let data = vec![0xABu8; 4096];
        let ptr = data.as_ptr();
        let len = data.len();

        // mlock should succeed for small buffers
        let lock_result = mlock_buffer(ptr, len);
        // On some CI environments this may fail due to privilege restrictions,
        // so we don't assert success. But if it succeeds, munlock must also succeed.
        if lock_result.is_ok() {
            assert!(munlock_buffer(ptr, len).is_ok());
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_mlock_small_key_material() {
        // Simulate locking a 32-byte AES key
        let key = [0u8; 32];
        let result = mlock_buffer(key.as_ptr(), key.len());
        if result.is_ok() {
            assert!(munlock_buffer(key.as_ptr(), key.len()).is_ok());
        }
    }
}
