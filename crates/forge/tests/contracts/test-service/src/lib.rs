// Path: crates/forge/tests/contracts/test-service/src/lib.rs
#![cfg(target_arch = "wasm32")]
#![no_std]
extern crate alloc;

#[macro_use]
extern crate ioi_contract_sdk;

use alloc::alloc::{alloc, dealloc};
use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

// --- Allocator Boilerplate Omitted (Same as above) ---
const HEAP_SIZE: usize = 32 * 1024;
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
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
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
    if ptr.is_null() {
        if new_size == 0 {
            return null_mut();
        }
        if let Some(new_layout) = layout(new_size, align) {
            return alloc(new_layout);
        }
        return null_mut();
    }
    if new_size == 0 {
        if let Some(old_layout) = layout(old_size, align) {
            dealloc(ptr, old_layout);
        }
        return null_mut();
    }
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
// Service implementation
// -----------------------------------------------------------------------------

use ioi_contract_sdk::{Guest, IoiService};

struct TestServiceV2;

impl IoiService for TestServiceV2 {
    fn id() -> String {
        String::from("fee_calculator_v2")
    }

    fn abi_version() -> u32 {
        1
    }

    fn state_schema() -> String {
        String::from("v1")
    }

    fn manifest() -> String {
        String::from(
            r#"
id = "fee_calculator"
abi_version = 1
state_schema = "v1"
runtime = "wasm"
capabilities = ["TxDecorator"]

[methods]
"ante_validate@v1" = "Internal"
"ante_write@v1" = "Internal"
"#,
        )
    }

    fn handle_service_call(_method: String, _params: Vec<u8>) -> Result<Vec<u8>, String> {
        Err(String::from("Not implemented"))
    }
}

struct Component;

impl Guest for Component {
    fn id() -> String {
        TestServiceV2::id()
    }
    fn abi_version() -> u32 {
        TestServiceV2::abi_version()
    }
    fn state_schema() -> String {
        TestServiceV2::state_schema()
    }
    fn manifest() -> String {
        TestServiceV2::manifest()
    }
    fn handle_service_call(method: String, params: Vec<u8>) -> Result<Vec<u8>, String> {
        TestServiceV2::handle_service_call(method, params)
    }
    fn prepare_upgrade(input: Vec<u8>) -> Vec<u8> {
        TestServiceV2::prepare_upgrade(input)
    }
    fn complete_upgrade(input: Vec<u8>) -> Vec<u8> {
        TestServiceV2::complete_upgrade(input)
    }
}

__export_service_impl!(Component with_types_in ioi_contract_sdk::bindings);
