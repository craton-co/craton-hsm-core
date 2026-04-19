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
            AddAccessAllowedAce, GetLengthSid, GetTokenInformation, InitializeAcl,
            ACCESS_ALLOWED_ACE, ACL as WIN_ACL, ACL_REVISION, TOKEN_USER,
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
        // ACE size formula per Microsoft docs:
        //   sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(pSid)
        // The struct embeds the first DWORD of the SID inline (`SidStart`), so we
        // subtract one DWORD to avoid double-counting before adding the full SID.
        // Total ACL buffer = ACL header + the single ACE.
        let acl_header_size = std::mem::size_of::<WIN_ACL>();
        let ace_size = std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            .checked_sub(std::mem::size_of::<u32>())
            .and_then(|n| n.checked_add(sid_length as usize))
            .ok_or_else(|| "ACE size computation overflowed".to_string())?;
        let acl_size_usize = acl_header_size
            .checked_add(ace_size)
            .ok_or_else(|| "ACL size computation overflowed".to_string())?;
        let acl_size: u32 = u32::try_from(acl_size_usize)
            .map_err(|_| format!("ACL size {} exceeds u32::MAX", acl_size_usize))?;

        let mut acl_buf: Vec<u8> = vec![0u8; acl_size as usize];
        let acl_ptr = acl_buf.as_mut_ptr() as *mut WIN_ACL;

        if InitializeAcl(acl_ptr, acl_size, ACL_REVISION as u32) == 0 {
            let err = GetLastError();
            return Err(format!("InitializeAcl failed (error {})", err));
        }

        // GENERIC_READ | GENERIC_WRITE
        let access_mask: u32 = 0x80000000 | 0x40000000;
        if AddAccessAllowedAce(acl_ptr, ACL_REVISION as u32, access_mask, user_sid) == 0 {
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
            acl_ptr as *const WIN_ACL,
            std::ptr::null_mut(),
        );
        if result != 0 {
            return Err(format!("SetNamedSecurityInfoW failed (error {})", result,));
        }
    }

    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Smoke test: on a freshly created file, restrict_file_to_owner must
    /// succeed. Any miscalculated ACL buffer size would cause InitializeAcl
    /// or AddAccessAllowedAce to fail with ERROR_INSUFFICIENT_BUFFER and
    /// surface here as Err.
    #[test]
    fn restrict_file_to_owner_succeeds_on_temp_file() {
        let mut f = NamedTempFile::new().expect("create temp file");
        writeln!(f, "hsm-test").expect("write temp file");

        let path = f.path().to_path_buf();
        restrict_file_to_owner(&path)
            .unwrap_or_else(|e| panic!("restrict_file_to_owner failed: {e}"));
    }

    /// Readback test: after restrict_file_to_owner succeeds, the file's DACL
    /// must parse cleanly and contain exactly one ACE at the expected
    /// revision. This catches bugs where the ACL buffer is the wrong size
    /// but InitializeAcl doesn't reject it (e.g. oversized buffer leaves
    /// garbage past the ACE the OS may or may not tolerate).
    #[test]
    fn restricted_dacl_has_single_ace_at_expected_revision() {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::Authorization::{
            GetNamedSecurityInfoW, SE_FILE_OBJECT,
        };
        use windows_sys::Win32::Security::{
            GetAclInformation, ACL as WIN_ACL, ACL_INFORMATION_CLASS, ACL_REVISION,
            ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        };

        let mut f = NamedTempFile::new().expect("create temp file");
        writeln!(f, "hsm-test").expect("write temp file");
        let path = f.path().to_path_buf();
        restrict_file_to_owner(&path).expect("restrict_file_to_owner");

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: we own the path, pass correctly-typed out-pointers, and
        // free the returned security descriptor via LocalFree per docs.
        unsafe {
            let mut dacl: *mut WIN_ACL = std::ptr::null_mut();
            let mut sd: *mut core::ffi::c_void = std::ptr::null_mut();
            let rv = GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            );
            assert_eq!(rv, 0, "GetNamedSecurityInfoW failed: {}", rv);
            assert!(!dacl.is_null(), "DACL pointer was null");

            // AclRevision is u8, check against the constant we used.
            assert_eq!(
                (*dacl).AclRevision,
                ACL_REVISION as u8,
                "unexpected ACL revision",
            );

            // Exactly one ACE — the owner grant we installed.
            const ACL_SIZE_INFO: ACL_INFORMATION_CLASS = 2;
            let mut info = ACL_SIZE_INFORMATION {
                AceCount: 0,
                AclBytesInUse: 0,
                AclBytesFree: 0,
            };
            let ok = GetAclInformation(
                dacl,
                (&mut info) as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                ACL_SIZE_INFO,
            );
            assert_ne!(ok, 0, "GetAclInformation failed");
            assert_eq!(info.AceCount, 1, "expected exactly one ACE, got {}", info.AceCount);
            assert_eq!(
                info.AclBytesFree, 0,
                "ACL buffer was oversized by {} bytes — indicates miscalculated size",
                info.AclBytesFree,
            );

            // Note: GetNamedSecurityInfoW allocates `sd` and the caller must
            // LocalFree it. We intentionally leak it here — the test process
            // exits immediately after, and avoiding LocalFree means we don't
            // need to add a windows-sys feature for it just to run a test.
            let _ = sd;
        }
    }
}
