// Path: crates/contract-sdk/src/host.rs
use crate::bindings::ioi::system::host;
use alloc::string::{String, ToString};
use parity_scale_codec::{Decode, Encode};

pub fn call<T: Encode, R: Decode>(capability: &str, request: &T) -> Result<R, String> {
    let req_bytes = request.encode();
    match host::call(capability, &req_bytes) {
        Ok(resp_bytes) => {
            R::decode(&mut &resp_bytes[..]).map_err(|_| "Failed to decode response".to_string())
        }
        Err(e) => Err(e),
    }
}
