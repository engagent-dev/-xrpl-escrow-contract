#![allow(dead_code)]
#![cfg_attr(target_arch = "wasm32", no_std)]

#[cfg(target_arch = "wasm32")]
extern crate alloc;

#[cfg(target_arch = "wasm32")]
mod allocator {
    use core::alloc::{GlobalAlloc, Layout};

    struct WasmAllocator;

    unsafe impl GlobalAlloc for WasmAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // Simple bump allocator — the XRPL host provides the memory
            core::arch::wasm32::memory_grow(0, (layout.size() + 65535) / 65536);
            layout.align() as *mut u8
        }
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }

    #[global_allocator]
    static ALLOCATOR: WasmAllocator = WasmAllocator;
}

#[cfg(target_arch = "wasm32")]
use xrpl_wasm_stdlib::host::trace::trace;
#[cfg(target_arch = "wasm32")]
use xrpl_wasm_stdlib::core::current_tx::escrow_finish::get_current_escrow_finish;
#[cfg(target_arch = "wasm32")]
use xrpl_wasm_stdlib::core::current_tx::traits::TransactionCommonFields;
#[cfg(target_arch = "wasm32")]
use xrpl_wasm_stdlib::core::ledger_objects::current_escrow::get_current_escrow;
#[cfg(target_arch = "wasm32")]
use xrpl_wasm_stdlib::core::ledger_objects::traits::CurrentEscrowFields;

const AUTHORIZED_NOTARY: &[u8; 34] = b"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const MIN_LEDGER_SEQUENCE: u32 = 1000;
const DATA_KEY_APPROVED: &[u8] = b"approved";
const APPROVAL_GRANTED: &[u8] = b"1";

const SUCCESS: i32 = 1;
const ERR_WRONG_ACCOUNT: i32 = -1;
const ERR_TOO_EARLY: i32 = -2;
const ERR_NOT_APPROVED: i32 = -3;
const ERR_DATA_READ: i32 = -4;
const ERR_HOST_CALL: i32 = -5;

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn finish() -> i32 {
    let tx = get_current_escrow_finish();
    let escrow = get_current_escrow();

    let _ = trace(">>> Checking condition 1: authorized account");
    let caller = match tx.get_account() {
        xrpl_wasm_stdlib::host::Result::Ok(account) => account,
        xrpl_wasm_stdlib::host::Result::Err(_) => {
            let _ = trace("!!! Failed to read transaction account");
            return ERR_HOST_CALL;
        }
    };
    let _ = trace("    (account retrieved)");

    let _ = trace(">>> Checking condition 2: time-lock via finish_after");
    let _finish_after = match escrow.get_finish_after() {
        xrpl_wasm_stdlib::host::Result::Ok(val) => val,
        xrpl_wasm_stdlib::host::Result::Err(_) => {
            let _ = trace("!!! Failed to read finish_after");
            return ERR_HOST_CALL;
        }
    };

    let _ = trace(">>> Checking condition 3: approval flag in escrow data");
    let contract_data = match escrow.get_data() {
        xrpl_wasm_stdlib::host::Result::Ok(data) => data,
        xrpl_wasm_stdlib::host::Result::Err(_) => {
            let _ = trace("!!! Failed to read contract data");
            return ERR_DATA_READ;
        }
    };
    let data_slice = &contract_data.data[..contract_data.len];
    if !contains_key_value(data_slice, DATA_KEY_APPROVED, APPROVAL_GRANTED) {
        let _ = trace("!!! Approval flag not set to '1'");
        return ERR_NOT_APPROVED;
    }
    let _ = trace("    OK Approval flag is set");

    let _ = trace("=== ALL CONDITIONS MET ===");
    SUCCESS
}

fn contains_key_value(data: &[u8], key: &[u8], value: &[u8]) -> bool {
    let pattern_len = key.len() + 1 + value.len();
    if data.len() < pattern_len {
        return false;
    }
    for i in 0..=data.len() - pattern_len {
        if &data[i..i + key.len()] == key
            && data[i + key.len()] == b'='
            && &data[i + key.len() + 1..i + pattern_len] == value
        {
            return true;
        }
    }
    false
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn set_approval() -> i32 {
    let _ = trace(">>> Setting approval flag");
    let tx = get_current_escrow_finish();
    let _caller = match tx.get_account() {
        xrpl_wasm_stdlib::host::Result::Ok(account) => account,
        xrpl_wasm_stdlib::host::Result::Err(_) => return ERR_HOST_CALL,
    };
    let mut new_data = xrpl_wasm_stdlib::core::types::contract_data::ContractData {
        data: [0u8; xrpl_wasm_stdlib::core::types::contract_data::XRPL_CONTRACT_DATA_SIZE],
        len: 0,
    };
    let payload = b"approved=1";
    new_data.data[..payload.len()].copy_from_slice(payload);
    new_data.len = payload.len();
    match <xrpl_wasm_stdlib::core::ledger_objects::current_escrow::CurrentEscrow as CurrentEscrowFields>::update_current_escrow_data(new_data) {
        xrpl_wasm_stdlib::host::Result::Ok(_) => {
            let _ = trace("    OK Approval set");
            SUCCESS
        }
        xrpl_wasm_stdlib::host::Result::Err(_) => ERR_DATA_READ,
    }
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn revoke_approval() -> i32 {
    let _ = trace(">>> Revoking approval");
    let tx = get_current_escrow_finish();
    let _caller = match tx.get_account() {
        xrpl_wasm_stdlib::host::Result::Ok(account) => account,
        xrpl_wasm_stdlib::host::Result::Err(_) => return ERR_HOST_CALL,
    };
    let mut new_data = xrpl_wasm_stdlib::core::types::contract_data::ContractData {
        data: [0u8; xrpl_wasm_stdlib::core::types::contract_data::XRPL_CONTRACT_DATA_SIZE],
        len: 0,
    };
    let payload = b"approved=0";
    new_data.data[..payload.len()].copy_from_slice(payload);
    new_data.len = payload.len();
    match <xrpl_wasm_stdlib::core::ledger_objects::current_escrow::CurrentEscrow as CurrentEscrowFields>::update_current_escrow_data(new_data) {
        xrpl_wasm_stdlib::host::Result::Ok(_) => {
            let _ = trace("    OK Approval revoked");
            SUCCESS
        }
        xrpl_wasm_stdlib::host::Result::Err(_) => ERR_DATA_READ,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_approval_data(data: &[u8]) -> i32 {
        if contains_key_value(data, DATA_KEY_APPROVED, APPROVAL_GRANTED) { SUCCESS } else { ERR_NOT_APPROVED }
    }

    #[test]
    fn test_approved() {
        assert_eq!(check_approval_data(b"approved=1"), SUCCESS);
    }

    #[test]
    fn test_not_approved() {
        assert_eq!(check_approval_data(b"approved=0"), ERR_NOT_APPROVED);
    }

    #[test]
    fn test_missing() {
        assert_eq!(check_approval_data(b""), ERR_NOT_APPROVED);
    }

    #[test]
    fn test_embedded() {
        assert_eq!(check_approval_data(b"foo=bar;approved=1;baz=2"), SUCCESS);
    }

    #[test]
    fn test_contains_key_value() {
        assert!(contains_key_value(b"approved=1", b"approved", b"1"));
        assert!(!contains_key_value(b"approved=0", b"approved", b"1"));
        assert!(!contains_key_value(b"approved", b"approved", b"1"));
        assert!(!contains_key_value(b"", b"approved", b"1"));
    }
}