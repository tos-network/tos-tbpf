// Copyright 2022 Tos Maintainers <info@tos.network>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Low-level memory management utilities for JIT compilation.
//!
//! This module provides platform-specific memory allocation functions that are
//! used by the JIT compiler to allocate executable memory pages. It includes
//! functions for page allocation, deallocation, and protection settings.
//!
//! # Safety
//!
//! Most functions in this module are unsafe as they directly interact with
//! OS memory management APIs and require careful handling of raw pointers.

#![cfg_attr(target_os = "windows", allow(dead_code))]

use crate::error::EbpfError;

#[cfg(not(target_os = "windows"))]
extern crate libc;
#[cfg(not(target_os = "windows"))]
use libc::c_void;

#[cfg(target_os = "windows")]
use winapi::{
    ctypes::c_void,
    shared::minwindef,
    um::{
        errhandlingapi::GetLastError,
        memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect},
        sysinfoapi::{GetSystemInfo, SYSTEM_INFO},
        winnt,
    },
};

#[cfg(not(target_os = "windows"))]
macro_rules! libc_error_guard {
    (succeeded?, mmap, $addr:expr, $($arg:expr),*) => {{
        *$addr = libc::mmap(*$addr, $($arg),*);
        *$addr != libc::MAP_FAILED
    }};
    (succeeded?, $function:ident, $($arg:expr),*) => {
        libc::$function($($arg),*) == 0
    };
    ($function:ident, $($arg:expr),* $(,)?) => {{
        const RETRY_COUNT: usize = 3;
        for i in 0..RETRY_COUNT {
            if libc_error_guard!(succeeded?, $function, $($arg),*) {
                break;
            } else if i.saturating_add(1) == RETRY_COUNT {
                let args = vec![$(format!("{:?}", $arg)),*];
                #[cfg(any(target_os = "freebsd", target_os = "ios", target_os = "macos"))]
                let errno = *libc::__error();
                #[cfg(any(target_os = "android", target_os = "netbsd", target_os = "openbsd"))]
                let errno = *libc::__errno();
                #[cfg(target_os = "linux")]
                let errno = *libc::__errno_location();
                return Err(EbpfError::LibcInvocationFailed(stringify!($function), args, errno));
            }
        }
    }};
}

#[cfg(target_os = "windows")]
macro_rules! winapi_error_guard {
    (succeeded?, VirtualAlloc, $addr:expr, $($arg:expr),*) => {{
        *$addr = VirtualAlloc(*$addr, $($arg),*);
        !(*$addr).is_null()
    }};
    (succeeded?, $function:ident, $($arg:expr),*) => {
        $function($($arg),*) != 0
    };
    ($function:ident, $($arg:expr),* $(,)?) => {{
        if !winapi_error_guard!(succeeded?, $function, $($arg),*) {
            let args = vec![$(format!("{:?}", $arg)),*];
            let errno = GetLastError();
            return Err(EbpfError::LibcInvocationFailed(stringify!($function), args, errno as i32));
        }
    }};
}

/// Returns the system page size in bytes.
///
/// This function queries the operating system for the memory page size,
/// which is typically 4096 bytes on most platforms.
///
/// # Returns
///
/// The system page size in bytes, guaranteed to be a power of two.
pub fn get_system_page_size() -> usize {
    #[cfg(not(target_os = "windows"))]
    // SAFETY: sysconf is a standard POSIX function that safely returns system configuration
    unsafe {
        libc::sysconf(libc::_SC_PAGESIZE) as usize
    }
    #[cfg(target_os = "windows")]
    // SAFETY: SYSTEM_INFO can be safely zero-initialized and GetSystemInfo fills it correctly
    unsafe {
        let mut system_info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut system_info);
        system_info.dwPageSize as usize
    }
}

/// Rounds a value up to the next multiple of the page size.
///
/// This function is used to ensure memory allocations are page-aligned.
///
/// # Arguments
///
/// * `value` - The value to round up
/// * `page_size` - The page size to round to (must be a power of two)
///
/// # Returns
///
/// The smallest multiple of `page_size` that is greater than or equal to `value`.
pub fn round_to_page_size(value: usize, page_size: usize) -> usize {
    value
        .saturating_add(page_size)
        .saturating_sub(1)
        .checked_div(page_size)
        .unwrap()
        .saturating_mul(page_size)
}

/// Allocates memory pages with proper error handling and validation.
///
/// # Safety
///
/// This function is unsafe because:
/// - It returns a raw pointer that the caller must manage
/// - The caller must ensure the pointer is freed with `free_pages`
/// - The allocated memory is uninitialized
///
/// # Pre-conditions
/// - `size_in_bytes` must be > 0 and <= MAX_ALLOCATION (1GB)
///
/// # Post-conditions
/// - Returns Ok(ptr) where ptr is page-aligned and non-null
/// - OR returns Err with appropriate error code
pub unsafe fn allocate_pages(size_in_bytes: usize) -> Result<*mut u8, EbpfError> {
    // Pre-condition check: validate allocation size
    const MAX_ALLOCATION: usize = 1 << 30; // 1GB limit
    if size_in_bytes == 0 {
        return Err(EbpfError::InvalidMemoryRegion(0));
    }
    if size_in_bytes > MAX_ALLOCATION {
        return Err(EbpfError::InvalidMemoryRegion(0));
    }

    let mut raw: *mut c_void = std::ptr::null_mut();
    #[cfg(not(target_os = "windows"))]
    libc_error_guard!(
        mmap,
        &mut raw,
        size_in_bytes,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
        -1,
        0,
    );
    #[cfg(target_os = "windows")]
    winapi_error_guard!(
        VirtualAlloc,
        &mut raw,
        size_in_bytes,
        winnt::MEM_RESERVE | winnt::MEM_COMMIT,
        winnt::PAGE_READWRITE,
    );

    // Post-condition validation
    debug_assert!(
        !raw.is_null(),
        "allocate_pages returned null after successful call"
    );
    debug_assert!(
        (raw as usize).is_multiple_of(get_system_page_size()),
        "allocate_pages returned non-page-aligned pointer: {:#x}",
        raw as usize
    );

    Ok(raw.cast::<u8>())
}

/// Frees memory pages previously allocated by `allocate_pages`.
///
/// # Safety
///
/// This function is unsafe because:
/// - The pointer must have been returned by a previous call to `allocate_pages`
/// - The size must exactly match the size used in the allocation
/// - The pointer must not be used after this call
/// - The memory must not be freed more than once
///
/// # Arguments
///
/// * `raw` - Pointer to the start of the allocated memory
/// * `size_in_bytes` - Size of the allocation in bytes (must match allocation size)
///
/// # Errors
///
/// Returns an error if the OS fails to free the memory.
pub unsafe fn free_pages(raw: *mut u8, size_in_bytes: usize) -> Result<(), EbpfError> {
    #[cfg(not(target_os = "windows"))]
    libc_error_guard!(munmap, raw.cast::<c_void>(), size_in_bytes);
    #[cfg(target_os = "windows")]
    winapi_error_guard!(
        VirtualFree,
        raw.cast::<c_void>(),
        size_in_bytes,
        winnt::MEM_RELEASE, // winnt::MEM_DECOMMIT
    );
    Ok(())
}

/// Protects memory pages with specified permissions (W^X enforcement).
///
/// # Safety
///
/// This function is unsafe because:
/// - It modifies page protections for arbitrary memory
/// - Incorrect usage can cause crashes or security vulnerabilities
///
/// # Pre-conditions
/// - `raw` must point to memory allocated by `allocate_pages`
/// - `raw` must be page-aligned
/// - `size_in_bytes` must be page-aligned and > 0
///
/// # Invariants
/// - W^X: Memory cannot be both writable and executable
/// - If `executable_flag` is true, memory becomes EXEC|READ
/// - If `executable_flag` is false, memory becomes READ-ONLY
pub unsafe fn protect_pages(
    raw: *mut u8,
    size_in_bytes: usize,
    executable_flag: bool,
) -> Result<(), EbpfError> {
    // Pre-condition validation
    let page_size = get_system_page_size();
    debug_assert!(!raw.is_null(), "protect_pages: null pointer");
    debug_assert!(size_in_bytes > 0, "protect_pages: zero size");
    debug_assert!(
        size_in_bytes.is_multiple_of(page_size),
        "protect_pages: size {} not page-aligned (page_size: {})",
        size_in_bytes,
        page_size
    );
    debug_assert!(
        (raw as usize).is_multiple_of(page_size),
        "protect_pages: pointer {:#x} not page-aligned (page_size: {})",
        raw as usize,
        page_size
    );

    #[cfg(not(target_os = "windows"))]
    {
        // W^X Invariant: memory is never both writable and executable
        libc_error_guard!(
            mprotect,
            raw.cast::<c_void>(),
            size_in_bytes,
            if executable_flag {
                libc::PROT_EXEC | libc::PROT_READ // Executable => Read-only
            } else {
                libc::PROT_READ // Not executable => Read-only
            },
        );
    }
    #[cfg(target_os = "windows")]
    {
        let mut old: minwindef::DWORD = 0;
        let ptr_old: *mut minwindef::DWORD = &mut old;
        // W^X Invariant: memory is never both writable and executable
        winapi_error_guard!(
            VirtualProtect,
            raw.cast::<c_void>(),
            size_in_bytes,
            if executable_flag {
                winnt::PAGE_EXECUTE_READ // Executable => Read-only
            } else {
                winnt::PAGE_READONLY // Not executable => Read-only
            },
            ptr_old,
        );
    }
    Ok(())
}
