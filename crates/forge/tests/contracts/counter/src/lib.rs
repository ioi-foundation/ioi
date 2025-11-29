// Path: crates/forge/tests/contracts/counter/src/lib.rs
#![no_std]
extern crate alloc;

// Import the exported wit-bindgen macro(s) from ioi-contract-sdk.
#[macro_use]
extern crate ioi_contract_sdk;

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use alloc::alloc::{alloc, dealloc};

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

// -----------------------------------------------------------------------------
// Minimal bump allocator: single static heap, no free().
// No env imports, so wit-component can componentize this module.
// -----------------------------------------------------------------------------
const HEAP_SIZE: usize = 32 * 1024; // 32 KiB heap

struct BumpAllocator {
    heap: UnsafeCell<[u8; HEAP_SIZE]>,
    offset: UnsafeCell<usize>,
}

unsafe impl Sync for BumpAllocator {}

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap_ptr = (*self.heap.get()).as_ptr() as usize;
        let offset = *self.offset.get();
        let align = layout.align();
        let size = layout.size();

        let aligned = (heap_ptr + offset + align - 1) & !(align - 1);
        let new_offset = aligned + size - heap_ptr;

        if new_offset > HEAP_SIZE {
            core::ptr::null_mut()
        } else {
            *self.offset.get() = new_offset;
            aligned as *mut u8
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // bump allocator: leak memory, no-op dealloc
    }
}

#[global_allocator]
static ALLOC: BumpAllocator = BumpAllocator {
    heap: UnsafeCell::new([0; HEAP_SIZE]),
    offset: UnsafeCell::new(0),
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// -----------------------------------------------------------------------------
// Canonical ABI allocator expected by `cargo component`.
// -----------------------------------------------------------------------------
#[no_mangle]
pub unsafe extern "C" fn cabi_realloc(
    ptr: *mut u8,
    old_size: usize,
    align: usize,
    new_size: usize,
) -> *mut u8 {
    use core::{cmp::min, ptr::null_mut};

    fn layout(size: usize, align: usize) -> Option<Layout> {
        Layout::from_size_align(size.max(1), align).ok()
    }

    // Allocate new
    if ptr.is_null() {
        if new_size == 0 {
            return null_mut();
        }
        if let Some(new_layout) = layout(new_size, align) {
            return alloc(new_layout);
        }
        return null_mut();
    }

    // Free
    if new_size == 0 {
        if let Some(old_layout) = layout(old_size, align) {
            dealloc(ptr, old_layout);
        }
        return null_mut();
    }

    // Reallocate: allocate new, copy, free old
    let Some(new_layout) = layout(new_size, align) else {
        return null_mut();
    };
    let new_ptr = alloc(new_layout);
    if new_ptr.is_null() {
        return null_mut();
    }

    let count = min(old_size, new_size);
    core::ptr::copy_nonoverlapping(ptr, new_ptr, count);

    if let Some(old_layout) = layout(old_size, align) {
        dealloc(ptr, old_layout);
    }

    new_ptr
}

// -----------------------------------------------------------------------------
// Contract implementation
// -----------------------------------------------------------------------------

use ioi_contract_sdk::Guest;

struct CounterContract;

// Key under which we store the counter value.
const COUNTER_KEY: &[u8] = b"counter_value";

impl Guest for CounterContract {
    fn id() -> String {
        "counter".to_string()
    }

    fn abi_version() -> u32 {
        1
    }

    fn state_schema() -> String {
        "v1".to_string()
    }

    fn manifest() -> String {
        // The current e2e test doesn’t inspect this.
        String::new()
    }

    fn handle_service_call(method: String, params: Vec<u8>) -> Result<Vec<u8>, String> {
        // Runtime entrypoint: method is usually "call".
        // e2e test encodes operation in params[0]:
        //   0 => get
        //   1 => increment
        if method == "call" && !params.is_empty() {
            return match params[0] {
                0 => {
                    // Get
                    let val_bytes = ioi_contract_sdk::state::get(COUNTER_KEY).unwrap_or(vec![0]);
                    Ok(val_bytes)
                }
                1 => {
                    // Increment
                    let val_bytes = ioi_contract_sdk::state::get(COUNTER_KEY).unwrap_or(vec![0]);
                    let mut val = val_bytes.first().copied().unwrap_or(0);

                    val = val.wrapping_add(1);

                    ioi_contract_sdk::state::set(COUNTER_KEY, &[val]);
                    Ok(vec![val])
                }
                _ => Err("Unknown opcode".to_string()),
            };
        }

        // Optional: string-based methods for future use.
        match method.as_str() {
            "get@v1" => {
                let val_bytes = ioi_contract_sdk::state::get(COUNTER_KEY).unwrap_or(vec![0]);
                Ok(val_bytes)
            }
            "increment@v1" => {
                let val_bytes = ioi_contract_sdk::state::get(COUNTER_KEY).unwrap_or(vec![0]);
                let mut val = val_bytes.first().copied().unwrap_or(0);
                val = val.wrapping_add(1);
                ioi_contract_sdk::state::set(COUNTER_KEY, &[val]);
                Ok(vec![val])
            }
            _ => Err("Unknown method".to_string()),
        }
    }

    fn prepare_upgrade(_input: Vec<u8>) -> Vec<u8> {
        Vec::new()
    }

    fn complete_upgrade(_input: Vec<u8>) -> Vec<u8> {
        Vec::new()
    }
}

// Export the component interface using the wit-bindgen-generated macro.
__export_service_impl!(CounterContract with_types_in ioi_contract_sdk::bindings);