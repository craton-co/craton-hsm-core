// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
/// Platform-specific file ACL restriction helpers.
///
/// On Windows, uses the Win32 Security API to set a protected DACL that grants
/// access only to the current user — the equivalent of Unix chmod 0o600.
///
/// This module is separated from the audit module because the audit module uses
/// `#![forbid(unsafe_code)]`, while the Win32 FFI calls require `unsafe`.
#[cfg(windows)]
use std::path::Path;

/// Restrict a file's DACL to the current process owner on Windows.
/// Returns an error string on failure so the caller can decide whether to
/// continue or abort.
#[cfg(windows)]
pub(crate) fn restrict_file_to_owner(path: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::HANDLE;

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: All FFI calls use valid, correctly-sized buffers. The file must
    // already exist (caller just created/opened it). These are well-documented
    // Win32 security APIs for setting file DACLs.
    unsafe {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
        use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
        use windows_sys::Win32::Security::{
            AddAccessAllowedAce, GetLengthSid, GetTokenInformation, InitializeAcl, ACL as WIN_ACL,
            TOKEN_USER,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        // Step 1: Get the current process token.
        let mut token_handle: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            0x0008, /* TOKEN_QUERY */
            &mut token_handle,
        ) == 0
        {
            let err = GetLastError();
            return Err(format!("OpenProcessToken failed (error {})", err));
        }

        // Step 2: Query token for user SID.
        let mut return_length: u32 = 0;
        let _ = GetTokenInformation(
            token_handle,
            1, /* TokenUser */
            std::ptr::null_mut(),
            0,
            &mut return_length,
        );
        if return_length == 0 {
            CloseHandle(token_handle);
            return Err("GetTokenInformation returned zero length".to_string());
        }

        let mut token_user_buf: Vec<u8> = vec![0u8; return_length as usize];
        if GetTokenInformation(
            token_handle,
            1, // TokenUser
            token_user_buf.as_mut_ptr() as *mut _,
            return_length,
            &mut return_length,
        ) == 0
        {
            let err = GetLastError();
            CloseHandle(token_handle);
            return Err(format!("GetTokenInformation failed (error {})", err));
        }

        // TOKEN_USER layout: first field is SID_AND_ATTRIBUTES { Sid: PSID, ... }.
        // Validate buffer is large enough for the TOKEN_USER struct before casting.
        if token_user_buf.len() < std::mem::size_of::<TOKEN_USER>() {
            CloseHandle(token_handle);
            return Err(format!(
                "token_user_buf too small ({} < {})",
                token_user_buf.len(),
                std::mem::size_of::<TOKEN_USER>()
            ));
        }
        let token_user = &*(token_user_buf.as_ptr() as *const TOKEN_USER);
        let user_sid = token_user.User.Sid;
        CloseHandle(token_handle);

        // Step 3: Build a minimal ACL with a single ALLOW entry for the owner.
        let sid_length = GetLengthSid(user_sid);
        // Validate SID length is reasonable (SID max is ~68 bytes per MS docs)
        if sid_length == 0 || sid_length > 256 {
            return Err(format!("unexpected SID length {}", sid_length));
        }
        // ACL header (8) + ACCESS_ALLOWED_ACE minus SidStart (8) + SID bytes.
        let acl_size: u32 = 8u32.saturating_add(8).saturating_add(sid_length);
        let mut acl_buf: Vec<u8> = vec![0u8; acl_size as usize];
        let acl_ptr = acl_buf.as_mut_ptr() as *mut WIN_ACL;

        if InitializeAcl(acl_ptr, acl_size, 2 /* ACL_REVISION */) == 0 {
            let err = GetLastError();
            return Err(format!("InitializeAcl failed (error {})", err));
        }

        // GENERIC_READ | GENERIC_WRITE
        let access_mask: u32 = 0x80000000 | 0x40000000;
        if AddAccessAllowedAce(acl_ptr, 2, access_mask, user_sid) == 0 {
            let err = GetLastError();
            return Err(format!("AddAccessAllowedAce failed (error {})", err));
        }

        // Step 4: Apply the protected DACL to the file.
        // SE_FILE_OBJECT=1, DACL_SECURITY_INFORMATION=4, PROTECTED_DACL=0x80000000
        let result = SetNamedSecurityInfoW(
            wide_path.as_ptr() as *const u16,
            1, // SE_FILE_OBJECT
            0x00000004 | 0x80000000,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl_ptr as *const _ as *const WIN_ACL,
            std::ptr::null_mut(),
        );
        if result != 0 {
            return Err(format!("SetNamedSecurityInfoW failed (error {})", result,));
        }
    }

    Ok(())
}
