// Path: crates/services/src/ibc/light_clients/wasm.rs

use async_trait::async_trait;
use ioi_api::error::CoreError;
use ioi_api::ibc::{LightClient, VerifyCtx};
use ioi_types::ibc::{Finality, Header, InclusionProof};
use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};

// Generate bindings for the WIT defined above
// Path is relative to the Cargo.toml of the crate (crates/services)
wasmtime::component::bindgen!({
    path: "../types/wit/ibc_verifier.wit",
    world: "verifier-module",
    async: true
});

pub struct WasmLightClient {
    engine: Engine,
    component: Component,
    chain_id_cache: String,
}

impl WasmLightClient {
    pub fn new(engine: &Engine, wasm_bytes: &[u8]) -> Result<Self, CoreError> {
        let component = Component::new(engine, wasm_bytes)
            .map_err(|e| CoreError::Custom(format!("WASM compilation failed: {}", e)))?;

        // We instantiate once temporarily to get the chain_id for the struct cache
        // In a real optimized impl, we might pass chain_id in constructor.
        let chain_id_cache = "dynamic-wasm-client".to_string();

        Ok(Self {
            engine: engine.clone(),
            component,
            chain_id_cache,
        })
    }

    async fn instantiate(&self) -> Result<(VerifierModule, Store<()>), CoreError> {
        let mut linker = Linker::new(&self.engine);
        let mut store = Store::new(&self.engine, ());
        // Strict fuel metering for dynamic verifiers
        store
            .set_fuel(50_000_000)
            .map_err(|_| CoreError::Custom("Fuel setup failed".into()))?;

        let (verifier, _) = VerifierModule::instantiate_async(&mut store, &self.component, &linker)
            .await
            .map_err(|e| CoreError::Custom(format!("WASM instantiation failed: {}", e)))?;

        Ok((verifier, store))
    }
}

#[async_trait]
impl LightClient for WasmLightClient {
    fn chain_id(&self) -> &str {
        &self.chain_id_cache
    }

    async fn verify_header(
        &self,
        header: &Header,
        _finality: &Finality,
        _ctx: &mut VerifyCtx,
    ) -> Result<(), CoreError> {
        let (verifier, mut store) = self.instantiate().await?;

        // Serialize header to generic bytes for the WASM boundary
        let header_bytes =
            ioi_types::codec::to_bytes_canonical(header).map_err(|e| CoreError::Custom(e))?;

        // TODO: Pass actual trusted state from context
        let trusted_state = vec![];

        let interface = verifier.ioi_ibc_light_client();

        interface
            .call_verify_header(&mut store, &header_bytes, &trusted_state)
            .await
            .map_err(|e| CoreError::Custom(format!("WASM runtime trap: {}", e)))?
            .map_err(|e| CoreError::Custom(format!("Verifier rejected header: {}", e)))?;

        Ok(())
    }

    async fn verify_inclusion(
        &self,
        proof: &InclusionProof,
        header: &Header,
        _ctx: &mut VerifyCtx,
    ) -> Result<(), CoreError> {
        let (verifier, mut store) = self.instantiate().await?;

        // Serialization logic...
        // In a real impl, we would properly serialize these.
        let proof_bytes = vec![]; // Placeholder
        let root_bytes = vec![]; // Placeholder
        let path_bytes = vec![];
        let value_bytes = vec![];

        let interface = verifier.ioi_ibc_light_client();

        let valid = interface
            .call_verify_membership(
                &mut store,
                &proof_bytes,
                &root_bytes,
                &path_bytes,
                &value_bytes,
            )
            .await
            .map_err(|e| CoreError::Custom(e.to_string()))?
            .map_err(|e| CoreError::Custom(e))?;

        if valid {
            Ok(())
        } else {
            Err(CoreError::Custom("WASM Verifier returned false".into()))
        }
    }

    async fn latest_verified_height(&self) -> u64 {
        0 // Handled by registry state
    }
}
