// Path: crates/macros/src/lib.rs
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse::Parse, parse::ParseStream, parse_macro_input, punctuated::Punctuated, FnArg, ImplItem,
    ItemImpl, LitInt, LitStr, Meta, Token,
};

struct ServiceAttributes {
    id: LitStr,
    abi_version: LitInt,
    state_schema: LitStr,
    capabilities: Option<LitStr>,
}

impl Parse for ServiceAttributes {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut id = None;
        let mut abi_version = None;
        let mut state_schema = None;
        let mut capabilities = None;

        let vars = Punctuated::<Meta, Token![,]>::parse_terminated(input)?;

        for var in vars {
            if let Meta::NameValue(nv) = var {
                if nv.path.is_ident("id") {
                    if let syn::Expr::Lit(expr_lit) = nv.value {
                        if let syn::Lit::Str(lit) = expr_lit.lit {
                            id = Some(lit);
                        }
                    }
                } else if nv.path.is_ident("abi_version") {
                    if let syn::Expr::Lit(expr_lit) = nv.value {
                        if let syn::Lit::Int(lit) = expr_lit.lit {
                            abi_version = Some(lit);
                        }
                    }
                } else if nv.path.is_ident("state_schema") {
                    if let syn::Expr::Lit(expr_lit) = nv.value {
                        if let syn::Lit::Str(lit) = expr_lit.lit {
                            state_schema = Some(lit);
                        }
                    }
                } else if nv.path.is_ident("capabilities") {
                    if let syn::Expr::Lit(expr_lit) = nv.value {
                        if let syn::Lit::Str(lit) = expr_lit.lit {
                            capabilities = Some(lit);
                        }
                    }
                }
            }
        }

        Ok(ServiceAttributes {
            id: id.ok_or_else(|| input.error("Missing `id` attribute"))?,
            abi_version: abi_version
                .ok_or_else(|| input.error("Missing `abi_version` attribute"))?,
            state_schema: state_schema
                .ok_or_else(|| input.error("Missing `state_schema` attribute"))?,
            capabilities,
        })
    }
}

#[proc_macro_attribute]
pub fn service_interface(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as ServiceAttributes);
    let mut item_impl = parse_macro_input!(input as ItemImpl);

    let struct_name = &item_impl.self_ty;
    let service_id = args.id.value();
    let abi_version = args.abi_version;
    let state_schema = args.state_schema;
    let caps_string = args
        .capabilities
        .as_ref()
        .map(|l| l.value())
        .unwrap_or_default();

    // Parse capabilities
    let mut cap_flags = quote! { ioi_types::service_configs::Capabilities::empty() };
    for cap in caps_string.split(',') {
        let trimmed = cap.trim();
        if !trimmed.is_empty() {
            let cap_ident = format_ident!("{}", trimmed);
            cap_flags =
                quote! { #cap_flags | ioi_types::service_configs::Capabilities::#cap_ident };
        }
    }

    // Generate capability downcasters
    let has_on_end_block = caps_string.contains("ON_END_BLOCK");
    let as_on_end_block = if has_on_end_block {
        quote! {
             fn as_on_end_block(&self) -> Option<&dyn ioi_api::lifecycle::OnEndBlock> {
                Some(self)
            }
        }
    } else {
        quote! {}
    };

    let has_tx_decorator = caps_string.contains("TX_DECORATOR");
    let as_tx_decorator = if has_tx_decorator {
        quote! {
             fn as_tx_decorator(&self) -> Option<&dyn ioi_api::transaction::decorator::TxDecorator> {
                Some(self)
            }
        }
    } else {
        quote! {}
    };

    let has_creds_view = caps_string.contains("CREDENTIALS_VIEW");
    let as_creds_view = if has_creds_view {
        quote! {
             fn as_credentials_view(&self) -> Option<&dyn ioi_api::identity::CredentialsView> {
                Some(self)
            }
        }
    } else {
        quote! {}
    };

    // Analyze methods
    let mut match_arms = Vec::new();

    for item in &mut item_impl.items {
        if let ImplItem::Fn(method) = item {
            let mut is_service_method = false;
            // Extract and remove #[method] attribute
            method.attrs.retain(|attr| {
                if attr.path().is_ident("method") {
                    is_service_method = true;
                    false
                } else {
                    true
                }
            });

            if is_service_method {
                let method_name = &method.sig.ident;
                // We expect the standard v1 versioning pattern: name + "@v1"
                let method_str = format!("{}@v1", method_name);

                // Inspect arguments to determine param type
                // Signature expected: fn name(&self, state: &mut dyn StateAccess, params: Type, ctx: &TxContext)
                let mut param_type = None;

                for (i, arg) in method.sig.inputs.iter().enumerate() {
                    if i == 2 {
                        if let FnArg::Typed(pat_type) = arg {
                            param_type = Some(*pat_type.ty.clone());
                        }
                    }
                }

                if let Some(p_type) = param_type {
                    // [MODIFIED] Changed .map_err(...) to .map_err(ioi_types::error::TransactionError::from)
                    // This allows the method to return Result<(), TransactionError> directly,
                    // or Result<(), String> which converts to TransactionError::Invalid(String).
                    match_arms.push(quote! {
                        #method_str => {
                            let p: #p_type = ioi_types::codec::from_bytes_canonical(params)?;
                            self.#method_name(state, p, ctx)
                                .map_err(ioi_types::error::TransactionError::from)?;
                            Ok(())
                        }
                    });
                } else {
                    // Method with no params argument?
                    // If signature is (&self, state, ctx)
                    match_arms.push(quote! {
                        #method_str => {
                             self.#method_name(state, ctx)
                                .map_err(ioi_types::error::TransactionError::from)?;
                            Ok(())
                        }
                    });
                }
            }
        }
    }

    let dispatch_impl = quote! {
        #[async_trait::async_trait]
        impl ioi_api::services::BlockchainService for #struct_name {
            fn id(&self) -> &str {
                #service_id
            }

            fn abi_version(&self) -> u32 {
                #abi_version
            }

            fn state_schema(&self) -> &str {
                #state_schema
            }

            fn capabilities(&self) -> ioi_types::service_configs::Capabilities {
                #cap_flags
            }

            fn as_any(&self) -> &dyn std::any::Any {
                self
            }

            #as_on_end_block
            #as_tx_decorator
            #as_creds_view

            async fn handle_service_call(
                &self,
                state: &mut dyn ioi_api::state::StateAccess,
                method: &str,
                params: &[u8],
                ctx: &mut ioi_api::transaction::context::TxContext<'_>,
            ) -> Result<(), ioi_types::error::TransactionError> {
                match method {
                    #(#match_arms)*
                    _ => Err(ioi_types::error::TransactionError::Unsupported(format!(
                        "Service '{}' does not support method '{}'",
                        self.id(),
                        method
                    ))),
                }
            }
        }
    };

    let output = quote! {
        #item_impl
        #dispatch_impl
    };

    TokenStream::from(output)
}

/// Procedural macro to drastically simplify writing WASM smart contracts for the IOI SDK.
///
/// This macro automatically:
/// 1. Injects a lightweight bump allocator and panic handler.
/// 2. Implements the `cabi_realloc` function required by the Component Model ABI.
/// 3. Generates the boilerplate `impl Guest` block that bridges the WIT exports to your
///    high-level `impl IoiService` trait.
/// 4. Calls the `export!` macro to finalize the component.
///
/// # Usage
/// Apply this to your `impl IoiService for MyContract`.
#[proc_macro_attribute]
pub fn ioi_contract(_args: TokenStream, input: TokenStream) -> TokenStream {
    let item_impl = parse_macro_input!(input as ItemImpl);
    let struct_type = &item_impl.self_ty;

    // 1. Define the BumpAllocator and GlobalAlloc implementation
    //    This provides a minimal, no-std compatible allocator for the WASM environment.
    let allocator_impl = quote! {
        const HEAP_SIZE: usize = 32 * 1024; // 32 KiB heap

        struct BumpAllocator {
            heap: core::cell::UnsafeCell<[u8; HEAP_SIZE]>,
            offset: core::cell::UnsafeCell<usize>,
        }

        unsafe impl Sync for BumpAllocator {}

        unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
            unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
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

            unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
                // bump allocator: leak memory, no-op dealloc
            }
        }

        #[global_allocator]
        static ALLOC: BumpAllocator = BumpAllocator {
            heap: core::cell::UnsafeCell::new([0; HEAP_SIZE]),
            offset: core::cell::UnsafeCell::new(0),
        };

        #[panic_handler]
        fn panic(_info: &core::panic::PanicInfo) -> ! {
            loop {}
        }
    };

    // 2. Define cabi_realloc for the Component Model ABI
    //    The host calls this to allocate memory in the guest for passing arguments.
    let cabi_realloc_impl = quote! {
        #[no_mangle]
        pub unsafe extern "C" fn cabi_realloc(
            ptr: *mut u8,
            old_size: usize,
            align: usize,
            new_size: usize,
        ) -> *mut u8 {
            use core::{cmp::min, ptr::null_mut};
            use alloc::alloc::{alloc, dealloc, Layout};

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
    };

    // 3. Bridge the IoiService trait to the generated Guest trait
    //    This connects the high-level `impl IoiService` to the low-level `impl Guest` required by wit-bindgen.
    let bridge_impl = quote! {
        // Wrapper struct to satisfy wit-bindgen requirements without modifying user code
        struct IoiContractComponent;

        impl ioi_contract_sdk::Guest for IoiContractComponent {
            fn id() -> alloc::string::String {
                <#struct_type as ioi_contract_sdk::IoiService>::id()
            }

            fn abi_version() -> u32 {
                <#struct_type as ioi_contract_sdk::IoiService>::abi_version()
            }

            fn state_schema() -> alloc::string::String {
                <#struct_type as ioi_contract_sdk::IoiService>::state_schema()
            }

            fn manifest() -> alloc::string::String {
                <#struct_type as ioi_contract_sdk::IoiService>::manifest()
            }

            fn handle_service_call(method: alloc::string::String, params: alloc::vec::Vec<u8>) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
                <#struct_type as ioi_contract_sdk::IoiService>::handle_service_call(method, params)
            }

            fn prepare_upgrade(input: alloc::vec::Vec<u8>) -> alloc::vec::Vec<u8> {
                <#struct_type as ioi_contract_sdk::IoiService>::prepare_upgrade(input)
            }

            fn complete_upgrade(input: alloc::vec::Vec<u8>) -> alloc::vec::Vec<u8> {
                <#struct_type as ioi_contract_sdk::IoiService>::complete_upgrade(input)
            }
        }

        // 4. Generate the export macro call
        //    This registers the component exports defined in the WIT file.
        ioi_contract_sdk::bindings::export!(IoiContractComponent with_types_in ioi_contract_sdk::bindings);
    };

    let output = quote! {
        #item_impl
        #allocator_impl
        #cabi_realloc_impl
        #bridge_impl
    };

    TokenStream::from(output)
}
