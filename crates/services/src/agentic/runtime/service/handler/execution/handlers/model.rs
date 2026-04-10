use super::super::{no_visual, ActionExecutionOutcome};
use crate::agentic::runtime::execution::workload;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::AgentState;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use ioi_api::vm::inference::{
    ImageEditRequest, ImageEmbeddingRequest, ImageGenerationRequest, ModelLoadRequest,
    ModelUnloadRequest, RerankRequest, SpeechSynthesisRequest, TextEmbeddingRequest,
    TextGenerationRequest, TranscriptionRequest, VideoGenerationRequest, VisionReadRequest,
};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{
    InferenceOperationKind, InferenceOptions, MediaOperationKind, ModelLifecycleOperationKind,
    RegistrySubjectKind, WorkloadActivityKind, WorkloadInferenceReceipt, WorkloadMediaReceipt,
    WorkloadModelLifecycleReceipt, WorkloadReceipt,
};
use ioi_types::error::TransactionError;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Instant;

const RECEIPT_PREVIEW_MAX_CHARS: usize = 256;
const RECEIPT_TEXT_MAX_CHARS: usize = 512;

pub(crate) async fn handle_native_dynamic_tool(
    service: &RuntimeAgentService,
    dynamic_tool: &Value,
    session_id: [u8; 32],
    step_index: u32,
    _agent_state: &AgentState,
) -> Result<Option<ActionExecutionOutcome>, TransactionError> {
    let Some(tool_name) = dynamic_tool_name(dynamic_tool) else {
        return Ok(None);
    };

    let outcome = match tool_name {
        "model__responses" => {
            Some(handle_model_responses_tool(service, dynamic_tool, session_id, step_index).await)
        }
        "model__embeddings" => {
            Some(handle_model_embeddings_tool(service, dynamic_tool, session_id, step_index).await)
        }
        "model__rerank" => {
            Some(handle_model_rerank_tool(service, dynamic_tool, session_id, step_index).await)
        }
        "media__transcribe_audio" => Some(
            handle_media_transcription_tool(service, dynamic_tool, session_id, step_index).await,
        ),
        "media__synthesize_speech" => {
            Some(handle_media_speech_tool(service, dynamic_tool, session_id, step_index).await)
        }
        "media__vision_read" => {
            Some(handle_media_vision_tool(service, dynamic_tool, session_id, step_index).await)
        }
        "media__generate_image" => Some(
            handle_media_image_generation_tool(service, dynamic_tool, session_id, step_index).await,
        ),
        "media__edit_image" => {
            Some(handle_media_image_edit_tool(service, dynamic_tool, session_id, step_index).await)
        }
        "media__generate_video" => Some(
            handle_media_video_generation_tool(service, dynamic_tool, session_id, step_index).await,
        ),
        _ => match classify_registry_tool(tool_name) {
            Some(descriptor) => Some(
                handle_registry_dynamic_tool(
                    service,
                    dynamic_tool,
                    session_id,
                    step_index,
                    descriptor,
                )
                .await,
            ),
            None => None,
        },
    };

    Ok(outcome)
}

#[derive(Debug, Clone, Copy)]
struct RegistryToolDescriptor {
    operation: ModelLifecycleOperationKind,
    subject_kind: RegistrySubjectKind,
    executable: RegistryExecutionMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryExecutionMode {
    LoadModel,
    UnloadModel,
    ControlPlaneAccepted,
}

fn classify_registry_tool(tool_name: &str) -> Option<RegistryToolDescriptor> {
    if let Some(suffix) = tool_name.strip_prefix("model_registry__") {
        return registry_descriptor_for_suffix(suffix, RegistrySubjectKind::Model);
    }
    if let Some(suffix) = tool_name.strip_prefix("backend__") {
        return registry_descriptor_for_suffix(suffix, RegistrySubjectKind::Backend);
    }
    if let Some(suffix) = tool_name.strip_prefix("gallery__") {
        return registry_descriptor_for_suffix(suffix, RegistrySubjectKind::Gallery);
    }
    None
}

fn registry_descriptor_for_suffix(
    suffix: &str,
    subject_kind: RegistrySubjectKind,
) -> Option<RegistryToolDescriptor> {
    let normalized = suffix.trim().to_ascii_lowercase();
    let (operation, executable) = match normalized.as_str() {
        "register" => (
            ModelLifecycleOperationKind::Register,
            RegistryExecutionMode::ControlPlaneAccepted,
        ),
        "install" | "import" => (
            ModelLifecycleOperationKind::Install,
            RegistryExecutionMode::ControlPlaneAccepted,
        ),
        "apply" | "activate" | "update" => (
            ModelLifecycleOperationKind::Apply,
            RegistryExecutionMode::ControlPlaneAccepted,
        ),
        "delete" | "remove" => (
            ModelLifecycleOperationKind::Delete,
            RegistryExecutionMode::ControlPlaneAccepted,
        ),
        "load" => (
            ModelLifecycleOperationKind::Load,
            if matches!(subject_kind, RegistrySubjectKind::Model) {
                RegistryExecutionMode::LoadModel
            } else {
                RegistryExecutionMode::ControlPlaneAccepted
            },
        ),
        "unload" => (
            ModelLifecycleOperationKind::Unload,
            if matches!(subject_kind, RegistrySubjectKind::Model) {
                RegistryExecutionMode::UnloadModel
            } else {
                RegistryExecutionMode::ControlPlaneAccepted
            },
        ),
        "start" => (
            ModelLifecycleOperationKind::Start,
            RegistryExecutionMode::ControlPlaneAccepted,
        ),
        "stop" => (
            ModelLifecycleOperationKind::Stop,
            RegistryExecutionMode::ControlPlaneAccepted,
        ),
        "health" | "health_check" | "probe" => (
            ModelLifecycleOperationKind::HealthCheck,
            RegistryExecutionMode::ControlPlaneAccepted,
        ),
        "sync" | "sync_gallery" | "refresh" => (
            ModelLifecycleOperationKind::SyncGallery,
            RegistryExecutionMode::ControlPlaneAccepted,
        ),
        _ => return None,
    };

    Some(RegistryToolDescriptor {
        operation,
        subject_kind,
        executable,
    })
}

async fn handle_model_responses_tool(
    service: &RuntimeAgentService,
    dynamic_tool: &Value,
    session_id: [u8; 32],
    step_index: u32,
) -> ActionExecutionOutcome {
    let tool_name = "model__responses";
    let arguments = dynamic_tool_arguments(dynamic_tool);
    let preview_seed = preview_text_argument(arguments)
        .unwrap_or_else(|| "kernel-native model response".to_string());
    let workload_id =
        compute_native_workload_id(service, session_id, step_index, tool_name, &preview_seed).await;
    emit_activity(service, session_id, step_index, &workload_id, "started");

    let requested_model_id = optional_string(arguments, "model_id");
    let model_hash = match resolve_model_hash(arguments) {
        Ok(hash) => hash,
        Err(error) => {
            let receipt = WorkloadInferenceReceipt {
                tool_name: tool_name.to_string(),
                operation: InferenceOperationKind::TextGeneration,
                backend: "kernel:first_party_inference".to_string(),
                model_id: requested_model_id.unwrap_or_else(|| "unresolved".to_string()),
                model_family: None,
                prompt_token_count: None,
                completion_token_count: None,
                total_token_count: None,
                vector_dimensions: None,
                result_item_count: 0,
                candidate_count_total: None,
                candidate_count_scored: None,
                streaming: optional_bool(arguments, "stream").unwrap_or(false),
                latency_ms: None,
                success: false,
                error_class: workload::extract_error_class(Some(&error)),
            };
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Inference(receipt),
            );
            return no_visual(false, None, Some(error));
        }
    };
    let model_id_for_receipt = requested_model_id
        .clone()
        .unwrap_or_else(|| hex::encode(model_hash));

    let request = match build_text_generation_request(arguments, model_hash, requested_model_id) {
        Ok(request) => request,
        Err(error) => {
            let receipt = WorkloadInferenceReceipt {
                tool_name: tool_name.to_string(),
                operation: InferenceOperationKind::TextGeneration,
                backend: "kernel:first_party_inference".to_string(),
                model_id: model_id_for_receipt,
                model_family: None,
                prompt_token_count: None,
                completion_token_count: None,
                total_token_count: None,
                vector_dimensions: None,
                result_item_count: 0,
                candidate_count_total: None,
                candidate_count_scored: None,
                streaming: optional_bool(arguments, "stream").unwrap_or(false),
                latency_ms: None,
                success: false,
                error_class: workload::extract_error_class(Some(&error)),
            };
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Inference(receipt),
            );
            return no_visual(false, None, Some(error));
        }
    };

    let started = Instant::now();
    match service.reasoning_inference.generate_text(request).await {
        Ok(result) => {
            let output_text = String::from_utf8_lossy(&result.output).to_string();
            let history_entry = json!({
                "output_text": output_text,
                "model_id": result.model_id,
                "streamed": result.streamed,
            })
            .to_string();
            let receipt = WorkloadInferenceReceipt {
                tool_name: tool_name.to_string(),
                operation: InferenceOperationKind::TextGeneration,
                backend: "kernel:first_party_inference".to_string(),
                model_id: result
                    .model_id
                    .clone()
                    .unwrap_or_else(|| model_id_for_receipt),
                model_family: None,
                prompt_token_count: None,
                completion_token_count: None,
                total_token_count: None,
                vector_dimensions: None,
                result_item_count: 1,
                candidate_count_total: None,
                candidate_count_scored: None,
                streaming: result.streamed,
                latency_ms: Some(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
                success: true,
                error_class: None,
            };
            emit_success_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Inference(receipt),
            );
            no_visual(true, Some(history_entry), None)
        }
        Err(error) => {
            let (error_message, error_class) = runtime_tool_failure(tool_name, &error.to_string());
            let receipt = WorkloadInferenceReceipt {
                tool_name: tool_name.to_string(),
                operation: InferenceOperationKind::TextGeneration,
                backend: "kernel:first_party_inference".to_string(),
                model_id: model_id_for_receipt,
                model_family: None,
                prompt_token_count: None,
                completion_token_count: None,
                total_token_count: None,
                vector_dimensions: None,
                result_item_count: 0,
                candidate_count_total: None,
                candidate_count_scored: None,
                streaming: optional_bool(arguments, "stream").unwrap_or(false),
                latency_ms: Some(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
                success: false,
                error_class: Some(error_class),
            };
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Inference(receipt),
            );
            no_visual(false, None, Some(error_message))
        }
    }
}

async fn handle_model_embeddings_tool(
    service: &RuntimeAgentService,
    dynamic_tool: &Value,
    session_id: [u8; 32],
    step_index: u32,
) -> ActionExecutionOutcome {
    let tool_name = "model__embeddings";
    let arguments = dynamic_tool_arguments(dynamic_tool);
    let preview_seed =
        preview_text_argument(arguments).unwrap_or_else(|| "kernel-native embedding".to_string());
    let workload_id =
        compute_native_workload_id(service, session_id, step_index, tool_name, &preview_seed).await;
    emit_activity(service, session_id, step_index, &workload_id, "started");

    let requested_model_id = optional_string(arguments, "model_id");
    let model_hash = match resolve_model_hash(arguments) {
        Ok(hash) => hash,
        Err(error) => {
            let receipt = WorkloadInferenceReceipt {
                tool_name: tool_name.to_string(),
                operation: InferenceOperationKind::EmbeddingText,
                backend: "kernel:first_party_inference".to_string(),
                model_id: requested_model_id.unwrap_or_else(|| "unresolved".to_string()),
                model_family: None,
                prompt_token_count: None,
                completion_token_count: None,
                total_token_count: None,
                vector_dimensions: None,
                result_item_count: 0,
                candidate_count_total: None,
                candidate_count_scored: None,
                streaming: false,
                latency_ms: None,
                success: false,
                error_class: workload::extract_error_class(Some(&error)),
            };
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Inference(receipt),
            );
            return no_visual(false, None, Some(error));
        }
    };
    let model_id_for_receipt = requested_model_id
        .clone()
        .unwrap_or_else(|| hex::encode(model_hash));

    let started = Instant::now();
    let image_bytes = image_bytes_argument(arguments, tool_name);
    let (operation, result) = match image_bytes {
        Some(Ok(image_bytes)) => (
            InferenceOperationKind::EmbeddingImage,
            service
                .reasoning_inference
                .embed_image_typed(ImageEmbeddingRequest {
                    image_bytes,
                    mime_type: optional_string(arguments, "mime_type"),
                    model_id: requested_model_id,
                })
                .await,
        ),
        Some(Err(error)) => {
            let receipt = WorkloadInferenceReceipt {
                tool_name: tool_name.to_string(),
                operation: InferenceOperationKind::EmbeddingImage,
                backend: "kernel:first_party_inference".to_string(),
                model_id: model_id_for_receipt,
                model_family: None,
                prompt_token_count: None,
                completion_token_count: None,
                total_token_count: None,
                vector_dimensions: None,
                result_item_count: 0,
                candidate_count_total: None,
                candidate_count_scored: None,
                streaming: false,
                latency_ms: None,
                success: false,
                error_class: workload::extract_error_class(Some(&error)),
            };
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Inference(receipt),
            );
            return no_visual(false, None, Some(error));
        }
        None => {
            let Some(text) = text_embedding_input(arguments) else {
                let error = invalid_arguments_error(
                    tool_name,
                    "requires a string 'text'/'input' field or an image payload.",
                );
                let receipt = WorkloadInferenceReceipt {
                    tool_name: tool_name.to_string(),
                    operation: InferenceOperationKind::EmbeddingText,
                    backend: "kernel:first_party_inference".to_string(),
                    model_id: model_id_for_receipt,
                    model_family: None,
                    prompt_token_count: None,
                    completion_token_count: None,
                    total_token_count: None,
                    vector_dimensions: None,
                    result_item_count: 0,
                    candidate_count_total: None,
                    candidate_count_scored: None,
                    streaming: false,
                    latency_ms: None,
                    success: false,
                    error_class: workload::extract_error_class(Some(&error)),
                };
                emit_failure_receipt(
                    service,
                    session_id,
                    step_index,
                    &workload_id,
                    WorkloadReceipt::Inference(receipt),
                );
                return no_visual(false, None, Some(error));
            };

            (
                InferenceOperationKind::EmbeddingText,
                service
                    .reasoning_inference
                    .embed_text_typed(TextEmbeddingRequest {
                        text,
                        model_id: requested_model_id,
                    })
                    .await,
            )
        }
    };

    match result {
        Ok(result) => {
            let history_entry = json!({
                "values": result.values,
                "dimensions": result.dimensions,
                "model_id": result.model_id,
            })
            .to_string();
            let receipt = WorkloadInferenceReceipt {
                tool_name: tool_name.to_string(),
                operation,
                backend: "kernel:first_party_inference".to_string(),
                model_id: result
                    .model_id
                    .clone()
                    .unwrap_or_else(|| model_id_for_receipt),
                model_family: None,
                prompt_token_count: None,
                completion_token_count: None,
                total_token_count: None,
                vector_dimensions: Some(result.dimensions),
                result_item_count: 1,
                candidate_count_total: None,
                candidate_count_scored: None,
                streaming: false,
                latency_ms: Some(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
                success: true,
                error_class: None,
            };
            emit_success_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Inference(receipt),
            );
            no_visual(true, Some(history_entry), None)
        }
        Err(error) => {
            let (error_message, error_class) = runtime_tool_failure(tool_name, &error.to_string());
            let receipt = WorkloadInferenceReceipt {
                tool_name: tool_name.to_string(),
                operation,
                backend: "kernel:first_party_inference".to_string(),
                model_id: model_id_for_receipt,
                model_family: None,
                prompt_token_count: None,
                completion_token_count: None,
                total_token_count: None,
                vector_dimensions: None,
                result_item_count: 0,
                candidate_count_total: None,
                candidate_count_scored: None,
                streaming: false,
                latency_ms: Some(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
                success: false,
                error_class: Some(error_class),
            };
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Inference(receipt),
            );
            no_visual(false, None, Some(error_message))
        }
    }
}

async fn handle_model_rerank_tool(
    service: &RuntimeAgentService,
    dynamic_tool: &Value,
    session_id: [u8; 32],
    step_index: u32,
) -> ActionExecutionOutcome {
    let tool_name = "model__rerank";
    let arguments = dynamic_tool_arguments(dynamic_tool);
    let preview_seed = preview_text_argument(arguments)
        .unwrap_or_else(|| "kernel-native rerank request".to_string());
    let workload_id =
        compute_native_workload_id(service, session_id, step_index, tool_name, &preview_seed).await;
    emit_activity(service, session_id, step_index, &workload_id, "started");

    let requested_model_id = optional_string(arguments, "model_id");
    let model_hash = match resolve_model_hash(arguments) {
        Ok(hash) => hash,
        Err(error) => {
            let receipt = WorkloadInferenceReceipt {
                tool_name: tool_name.to_string(),
                operation: InferenceOperationKind::Rerank,
                backend: "kernel:first_party_inference".to_string(),
                model_id: requested_model_id.unwrap_or_else(|| "unresolved".to_string()),
                model_family: None,
                prompt_token_count: None,
                completion_token_count: None,
                total_token_count: None,
                vector_dimensions: None,
                result_item_count: 0,
                candidate_count_total: None,
                candidate_count_scored: None,
                streaming: false,
                latency_ms: None,
                success: false,
                error_class: workload::extract_error_class(Some(&error)),
            };
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Inference(receipt),
            );
            return no_visual(false, None, Some(error));
        }
    };
    let model_id_for_receipt = requested_model_id
        .clone()
        .unwrap_or_else(|| hex::encode(model_hash));

    let query = match optional_string(arguments, "query") {
        Some(query) if !query.trim().is_empty() => query,
        _ => {
            let error = invalid_arguments_error(tool_name, "requires a non-empty 'query'.");
            let receipt = WorkloadInferenceReceipt {
                tool_name: tool_name.to_string(),
                operation: InferenceOperationKind::Rerank,
                backend: "kernel:first_party_inference".to_string(),
                model_id: model_id_for_receipt,
                model_family: None,
                prompt_token_count: None,
                completion_token_count: None,
                total_token_count: None,
                vector_dimensions: None,
                result_item_count: 0,
                candidate_count_total: None,
                candidate_count_scored: None,
                streaming: false,
                latency_ms: None,
                success: false,
                error_class: workload::extract_error_class(Some(&error)),
            };
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Inference(receipt),
            );
            return no_visual(false, None, Some(error));
        }
    };
    let candidates = match string_array_argument(arguments, "candidates") {
        Ok(candidates) if !candidates.is_empty() => candidates,
        Ok(_) => {
            let error =
                invalid_arguments_error(tool_name, "requires a non-empty 'candidates' array.");
            let receipt = WorkloadInferenceReceipt {
                tool_name: tool_name.to_string(),
                operation: InferenceOperationKind::Rerank,
                backend: "kernel:first_party_inference".to_string(),
                model_id: model_id_for_receipt,
                model_family: None,
                prompt_token_count: None,
                completion_token_count: None,
                total_token_count: None,
                vector_dimensions: None,
                result_item_count: 0,
                candidate_count_total: None,
                candidate_count_scored: None,
                streaming: false,
                latency_ms: None,
                success: false,
                error_class: Some("InvalidArguments".to_string()),
            };
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Inference(receipt),
            );
            return no_visual(false, None, Some(error));
        }
        Err(error) => {
            let receipt = WorkloadInferenceReceipt {
                tool_name: tool_name.to_string(),
                operation: InferenceOperationKind::Rerank,
                backend: "kernel:first_party_inference".to_string(),
                model_id: model_id_for_receipt,
                model_family: None,
                prompt_token_count: None,
                completion_token_count: None,
                total_token_count: None,
                vector_dimensions: None,
                result_item_count: 0,
                candidate_count_total: None,
                candidate_count_scored: None,
                streaming: false,
                latency_ms: None,
                success: false,
                error_class: workload::extract_error_class(Some(&error)),
            };
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Inference(receipt),
            );
            return no_visual(false, None, Some(error));
        }
    };

    let started = Instant::now();
    let candidate_count_total = candidates.len().min(u32::MAX as usize) as u32;
    match service
        .reasoning_inference
        .rerank(RerankRequest {
            query,
            candidates,
            top_k: optional_u32(arguments, "top_k"),
            model_id: requested_model_id,
        })
        .await
    {
        Ok(result) => {
            let item_count = result.items.len().min(u32::MAX as usize) as u32;
            let history_entry = json!({
                "items": result.items,
                "model_id": result.model_id,
            })
            .to_string();
            let receipt = WorkloadInferenceReceipt {
                tool_name: tool_name.to_string(),
                operation: InferenceOperationKind::Rerank,
                backend: "kernel:first_party_inference".to_string(),
                model_id: result
                    .model_id
                    .clone()
                    .unwrap_or_else(|| model_id_for_receipt),
                model_family: None,
                prompt_token_count: None,
                completion_token_count: None,
                total_token_count: None,
                vector_dimensions: None,
                result_item_count: item_count,
                candidate_count_total: Some(candidate_count_total),
                candidate_count_scored: Some(candidate_count_total),
                streaming: false,
                latency_ms: Some(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
                success: true,
                error_class: None,
            };
            emit_success_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Inference(receipt),
            );
            no_visual(true, Some(history_entry), None)
        }
        Err(error) => {
            let (error_message, error_class) = runtime_tool_failure(tool_name, &error.to_string());
            let receipt = WorkloadInferenceReceipt {
                tool_name: tool_name.to_string(),
                operation: InferenceOperationKind::Rerank,
                backend: "kernel:first_party_inference".to_string(),
                model_id: model_id_for_receipt,
                model_family: None,
                prompt_token_count: None,
                completion_token_count: None,
                total_token_count: None,
                vector_dimensions: None,
                result_item_count: 0,
                candidate_count_total: Some(candidate_count_total),
                candidate_count_scored: None,
                streaming: false,
                latency_ms: Some(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
                success: false,
                error_class: Some(error_class),
            };
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Inference(receipt),
            );
            no_visual(false, None, Some(error_message))
        }
    }
}

async fn handle_media_transcription_tool(
    service: &RuntimeAgentService,
    dynamic_tool: &Value,
    session_id: [u8; 32],
    step_index: u32,
) -> ActionExecutionOutcome {
    let tool_name = "media__transcribe_audio";
    let arguments = dynamic_tool_arguments(dynamic_tool);
    let preview_seed = preview_text_argument(arguments)
        .unwrap_or_else(|| "kernel-native transcription".to_string());
    let workload_id =
        compute_native_workload_id(service, session_id, step_index, tool_name, &preview_seed).await;
    emit_activity(service, session_id, step_index, &workload_id, "started");

    let audio_bytes = match audio_bytes_argument(arguments, tool_name) {
        Ok(bytes) => bytes,
        Err(error) => {
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::Transcription,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 0,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: None,
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: workload::extract_error_class(Some(&error)),
                }),
            );
            return no_visual(false, None, Some(error));
        }
    };
    let mime_type = match required_string_argument(arguments, "mime_type", tool_name) {
        Ok(value) => value,
        Err(error) => {
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::Transcription,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: None,
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: workload::extract_error_class(Some(&error)),
                }),
            );
            return no_visual(false, None, Some(error));
        }
    };

    let started = Instant::now();
    match service
        .reasoning_inference
        .transcribe_audio(TranscriptionRequest {
            audio_bytes,
            mime_type,
            language: optional_string(arguments, "language"),
            model_id: optional_string(arguments, "model_id"),
        })
        .await
    {
        Ok(result) => {
            let (preview, truncated) = truncate_chars(&result.text, 160);
            let history_entry = json!({
                "text_preview": preview,
                "text_truncated": truncated,
                "language": result.language,
                "model_id": result.model_id,
            })
            .to_string();
            emit_success_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::Transcription,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: result.model_id,
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1,
                    output_artifact_count: 1,
                    output_bytes: Some(result.text.len().min(u64::MAX as usize) as u64),
                    duration_ms: Some(
                        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                    ),
                    output_mime_types: vec!["text/plain".to_string()],
                    success: true,
                    error_class: None,
                }),
            );
            no_visual(true, Some(history_entry), None)
        }
        Err(error) => {
            let (error_message, error_class) = runtime_tool_failure(tool_name, &error.to_string());
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::Transcription,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: Some(
                        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                    ),
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: Some(error_class),
                }),
            );
            no_visual(false, None, Some(error_message))
        }
    }
}

async fn handle_media_speech_tool(
    service: &RuntimeAgentService,
    dynamic_tool: &Value,
    session_id: [u8; 32],
    step_index: u32,
) -> ActionExecutionOutcome {
    let tool_name = "media__synthesize_speech";
    let arguments = dynamic_tool_arguments(dynamic_tool);
    let preview_seed = preview_text_argument(arguments)
        .unwrap_or_else(|| "kernel-native speech synthesis".to_string());
    let workload_id =
        compute_native_workload_id(service, session_id, step_index, tool_name, &preview_seed).await;
    emit_activity(service, session_id, step_index, &workload_id, "started");

    let text = match required_string_argument(arguments, "text", tool_name) {
        Ok(value) => value,
        Err(error) => {
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::SpeechSynthesis,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 0,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: None,
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: workload::extract_error_class(Some(&error)),
                }),
            );
            return no_visual(false, None, Some(error));
        }
    };

    let started = Instant::now();
    match service
        .reasoning_inference
        .synthesize_speech(SpeechSynthesisRequest {
            text,
            voice: optional_string(arguments, "voice"),
            mime_type: optional_string(arguments, "mime_type"),
            model_id: optional_string(arguments, "model_id"),
        })
        .await
    {
        Ok(result) => {
            let history_entry = json!({
                "mime_type": result.mime_type,
                "byte_count": result.audio_bytes.len(),
                "model_id": result.model_id,
            })
            .to_string();
            emit_success_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::SpeechSynthesis,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: result.model_id,
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1,
                    output_artifact_count: 1,
                    output_bytes: Some(result.audio_bytes.len().min(u64::MAX as usize) as u64),
                    duration_ms: Some(
                        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                    ),
                    output_mime_types: vec![result.mime_type],
                    success: true,
                    error_class: None,
                }),
            );
            no_visual(true, Some(history_entry), None)
        }
        Err(error) => {
            let (error_message, error_class) = runtime_tool_failure(tool_name, &error.to_string());
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::SpeechSynthesis,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: Some(
                        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                    ),
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: Some(error_class),
                }),
            );
            no_visual(false, None, Some(error_message))
        }
    }
}

async fn handle_media_vision_tool(
    service: &RuntimeAgentService,
    dynamic_tool: &Value,
    session_id: [u8; 32],
    step_index: u32,
) -> ActionExecutionOutcome {
    let tool_name = "media__vision_read";
    let arguments = dynamic_tool_arguments(dynamic_tool);
    let preview_seed =
        preview_text_argument(arguments).unwrap_or_else(|| "kernel-native vision read".to_string());
    let workload_id =
        compute_native_workload_id(service, session_id, step_index, tool_name, &preview_seed).await;
    emit_activity(service, session_id, step_index, &workload_id, "started");

    let image_bytes = match required_binary_argument(
        image_bytes_argument(arguments, tool_name),
        tool_name,
        "requires an image payload.",
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::VisionRead,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 0,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: None,
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: workload::extract_error_class(Some(&error)),
                }),
            );
            return no_visual(false, None, Some(error));
        }
    };
    let mime_type = optional_string(arguments, "mime_type")
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let started = Instant::now();
    match service
        .reasoning_inference
        .vision_read(VisionReadRequest {
            image_bytes,
            mime_type,
            prompt: optional_string(arguments, "prompt"),
            model_id: optional_string(arguments, "model_id"),
        })
        .await
    {
        Ok(result) => {
            let (preview, truncated) = truncate_chars(&result.output_text, 160);
            let history_entry = json!({
                "output_text_preview": preview,
                "output_truncated": truncated,
                "model_id": result.model_id,
            })
            .to_string();
            emit_success_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::VisionRead,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: result.model_id,
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1,
                    output_artifact_count: 1,
                    output_bytes: Some(result.output_text.len().min(u64::MAX as usize) as u64),
                    duration_ms: Some(
                        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                    ),
                    output_mime_types: vec!["text/plain".to_string()],
                    success: true,
                    error_class: None,
                }),
            );
            no_visual(true, Some(history_entry), None)
        }
        Err(error) => {
            let (error_message, error_class) = runtime_tool_failure(tool_name, &error.to_string());
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::VisionRead,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: Some(
                        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                    ),
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: Some(error_class),
                }),
            );
            no_visual(false, None, Some(error_message))
        }
    }
}

async fn handle_media_image_generation_tool(
    service: &RuntimeAgentService,
    dynamic_tool: &Value,
    session_id: [u8; 32],
    step_index: u32,
) -> ActionExecutionOutcome {
    let tool_name = "media__generate_image";
    let arguments = dynamic_tool_arguments(dynamic_tool);
    let preview_seed = preview_text_argument(arguments)
        .unwrap_or_else(|| "kernel-native image generation".to_string());
    let workload_id =
        compute_native_workload_id(service, session_id, step_index, tool_name, &preview_seed).await;
    emit_activity(service, session_id, step_index, &workload_id, "started");

    let prompt = match required_string_argument(arguments, "prompt", tool_name) {
        Ok(value) => value,
        Err(error) => {
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::ImageGeneration,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 0,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: None,
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: workload::extract_error_class(Some(&error)),
                }),
            );
            return no_visual(false, None, Some(error));
        }
    };

    let started = Instant::now();
    match service
        .reasoning_inference
        .generate_image(ImageGenerationRequest {
            prompt,
            mime_type: optional_string(arguments, "mime_type"),
            model_id: optional_string(arguments, "model_id"),
        })
        .await
    {
        Ok(result) => {
            let history_entry = json!({
                "mime_type": result.mime_type,
                "byte_count": result.image_bytes.len(),
                "model_id": result.model_id,
            })
            .to_string();
            emit_success_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::ImageGeneration,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: result.model_id,
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1,
                    output_artifact_count: 1,
                    output_bytes: Some(result.image_bytes.len().min(u64::MAX as usize) as u64),
                    duration_ms: Some(
                        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                    ),
                    output_mime_types: vec![result.mime_type],
                    success: true,
                    error_class: None,
                }),
            );
            no_visual(true, Some(history_entry), None)
        }
        Err(error) => {
            let (error_message, error_class) = runtime_tool_failure(tool_name, &error.to_string());
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::ImageGeneration,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: Some(
                        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                    ),
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: Some(error_class),
                }),
            );
            no_visual(false, None, Some(error_message))
        }
    }
}

async fn handle_media_image_edit_tool(
    service: &RuntimeAgentService,
    dynamic_tool: &Value,
    session_id: [u8; 32],
    step_index: u32,
) -> ActionExecutionOutcome {
    let tool_name = "media__edit_image";
    let arguments = dynamic_tool_arguments(dynamic_tool);
    let preview_seed =
        preview_text_argument(arguments).unwrap_or_else(|| "kernel-native image edit".to_string());
    let workload_id =
        compute_native_workload_id(service, session_id, step_index, tool_name, &preview_seed).await;
    emit_activity(service, session_id, step_index, &workload_id, "started");

    let source_image_bytes = match base64_or_byte_array_argument(
        arguments,
        "source_image_base64",
        "source_image_bytes",
        tool_name,
        "source image",
    ) {
        Some(Ok(bytes)) => bytes,
        Some(Err(error)) => {
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::ImageEdit,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 0,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: None,
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: workload::extract_error_class(Some(&error)),
                }),
            );
            return no_visual(false, None, Some(error));
        }
        None => {
            let error = invalid_arguments_error(tool_name, "requires a source image payload.");
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::ImageEdit,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 0,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: None,
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: workload::extract_error_class(Some(&error)),
                }),
            );
            return no_visual(false, None, Some(error));
        }
    };
    let source_mime_type = match required_string_argument(arguments, "source_mime_type", tool_name)
    {
        Ok(value) => value,
        Err(error) => {
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::ImageEdit,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: None,
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: workload::extract_error_class(Some(&error)),
                }),
            );
            return no_visual(false, None, Some(error));
        }
    };
    let mask_image_bytes = match base64_or_byte_array_argument(
        arguments,
        "mask_image_base64",
        "mask_image_bytes",
        tool_name,
        "mask image",
    ) {
        Some(Ok(bytes)) => Some(bytes),
        Some(Err(error)) => {
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::ImageEdit,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: None,
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: workload::extract_error_class(Some(&error)),
                }),
            );
            return no_visual(false, None, Some(error));
        }
        None => None,
    };

    let started = Instant::now();
    match service
        .reasoning_inference
        .edit_image(ImageEditRequest {
            source_image_bytes,
            source_mime_type,
            prompt: optional_string(arguments, "prompt"),
            mask_image_bytes,
            model_id: optional_string(arguments, "model_id"),
        })
        .await
    {
        Ok(result) => {
            let history_entry = json!({
                "mime_type": result.mime_type,
                "byte_count": result.image_bytes.len(),
                "model_id": result.model_id,
            })
            .to_string();
            emit_success_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::ImageEdit,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: result.model_id,
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1u32
                        + u32::from(
                            optional_string(arguments, "mask_image_base64").is_some()
                                || arguments.get("mask_image_bytes").is_some(),
                        ),
                    output_artifact_count: 1,
                    output_bytes: Some(result.image_bytes.len().min(u64::MAX as usize) as u64),
                    duration_ms: Some(
                        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                    ),
                    output_mime_types: vec![result.mime_type],
                    success: true,
                    error_class: None,
                }),
            );
            no_visual(true, Some(history_entry), None)
        }
        Err(error) => {
            let (error_message, error_class) = runtime_tool_failure(tool_name, &error.to_string());
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::ImageEdit,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: Some(
                        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                    ),
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: Some(error_class),
                }),
            );
            no_visual(false, None, Some(error_message))
        }
    }
}

async fn handle_media_video_generation_tool(
    service: &RuntimeAgentService,
    dynamic_tool: &Value,
    session_id: [u8; 32],
    step_index: u32,
) -> ActionExecutionOutcome {
    let tool_name = "media__generate_video";
    let arguments = dynamic_tool_arguments(dynamic_tool);
    let preview_seed = preview_text_argument(arguments)
        .unwrap_or_else(|| "kernel-native video generation".to_string());
    let workload_id =
        compute_native_workload_id(service, session_id, step_index, tool_name, &preview_seed).await;
    emit_activity(service, session_id, step_index, &workload_id, "started");

    let prompt = match required_string_argument(arguments, "prompt", tool_name) {
        Ok(value) => value,
        Err(error) => {
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::VideoGeneration,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 0,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: None,
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: workload::extract_error_class(Some(&error)),
                }),
            );
            return no_visual(false, None, Some(error));
        }
    };

    let started = Instant::now();
    match service
        .reasoning_inference
        .generate_video(VideoGenerationRequest {
            prompt,
            mime_type: optional_string(arguments, "mime_type"),
            duration_ms: optional_u64(arguments, "duration_ms"),
            model_id: optional_string(arguments, "model_id"),
        })
        .await
    {
        Ok(result) => {
            let history_entry = json!({
                "mime_type": result.mime_type,
                "byte_count": result.video_bytes.len(),
                "model_id": result.model_id,
            })
            .to_string();
            emit_success_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::VideoGeneration,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: result.model_id,
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1,
                    output_artifact_count: 1,
                    output_bytes: Some(result.video_bytes.len().min(u64::MAX as usize) as u64),
                    duration_ms: Some(
                        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                    ),
                    output_mime_types: vec![result.mime_type],
                    success: true,
                    error_class: None,
                }),
            );
            no_visual(true, Some(history_entry), None)
        }
        Err(error) => {
            let (error_message, error_class) = runtime_tool_failure(tool_name, &error.to_string());
            emit_failure_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::Media(WorkloadMediaReceipt {
                    tool_name: tool_name.to_string(),
                    operation: MediaOperationKind::VideoGeneration,
                    backend: "kernel:first_party_media".to_string(),
                    model_id: optional_string(arguments, "model_id"),
                    source_uri: optional_string(arguments, "source_uri"),
                    input_artifact_count: 1,
                    output_artifact_count: 0,
                    output_bytes: None,
                    duration_ms: Some(
                        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                    ),
                    output_mime_types: Vec::new(),
                    success: false,
                    error_class: Some(error_class),
                }),
            );
            no_visual(false, None, Some(error_message))
        }
    }
}

async fn handle_registry_dynamic_tool(
    service: &RuntimeAgentService,
    dynamic_tool: &Value,
    session_id: [u8; 32],
    step_index: u32,
    descriptor: RegistryToolDescriptor,
) -> ActionExecutionOutcome {
    let tool_name = dynamic_tool_name(dynamic_tool).unwrap_or("model_registry__unknown");
    let arguments = dynamic_tool_arguments(dynamic_tool);
    let subject_id = registry_subject_id(arguments, descriptor.subject_kind, tool_name);
    let source_uri = registry_source_uri(arguments);
    let preview_seed = source_uri.clone().unwrap_or_else(|| subject_id.clone());
    let workload_id =
        compute_native_workload_id(service, session_id, step_index, tool_name, &preview_seed).await;
    emit_activity(service, session_id, step_index, &workload_id, "started");

    match descriptor.executable {
        RegistryExecutionMode::LoadModel => {
            let model_id = optional_string(arguments, "model_id");
            let model_hash = match resolve_model_hash(arguments) {
                Ok(hash) => hash,
                Err(error) => {
                    let receipt = WorkloadModelLifecycleReceipt {
                        tool_name: tool_name.to_string(),
                        operation: descriptor.operation,
                        subject_kind: descriptor.subject_kind,
                        subject_id,
                        backend_id: optional_string(arguments, "backend_id"),
                        source_uri,
                        job_id: optional_string(arguments, "job_id"),
                        bytes_transferred: optional_u64(arguments, "bytes_transferred"),
                        hardware_profile: optional_string(arguments, "hardware_profile"),
                        success: false,
                        error_class: workload::extract_error_class(Some(&error)),
                    };
                    emit_failure_receipt(
                        service,
                        session_id,
                        step_index,
                        &workload_id,
                        WorkloadReceipt::ModelLifecycle(receipt),
                    );
                    return no_visual(false, None, Some(error));
                }
            };
            let model_id_for_receipt = model_id.clone().unwrap_or_else(|| hex::encode(model_hash));
            let Some(path) = registry_load_path(arguments) else {
                let error = invalid_arguments_error(
                    tool_name,
                    "requires 'path', 'artifact_path', or 'source_uri' for load.",
                );
                let receipt = WorkloadModelLifecycleReceipt {
                    tool_name: tool_name.to_string(),
                    operation: descriptor.operation,
                    subject_kind: descriptor.subject_kind,
                    subject_id: model_id_for_receipt,
                    backend_id: optional_string(arguments, "backend_id"),
                    source_uri,
                    job_id: optional_string(arguments, "job_id"),
                    bytes_transferred: optional_u64(arguments, "bytes_transferred"),
                    hardware_profile: optional_string(arguments, "hardware_profile"),
                    success: false,
                    error_class: workload::extract_error_class(Some(&error)),
                };
                emit_failure_receipt(
                    service,
                    session_id,
                    step_index,
                    &workload_id,
                    WorkloadReceipt::ModelLifecycle(receipt),
                );
                return no_visual(false, None, Some(error));
            };
            let started = Instant::now();
            match service
                .reasoning_inference
                .load_registered_model(ModelLoadRequest {
                    model_hash,
                    path,
                    model_id,
                })
                .await
            {
                Ok(result) => {
                    let history_entry = json!({
                        "operation": result.operation.as_label(),
                        "subject_kind": result.subject_kind.as_label(),
                        "subject_id": result.subject_id,
                    })
                    .to_string();
                    let receipt = WorkloadModelLifecycleReceipt {
                        tool_name: tool_name.to_string(),
                        operation: result.operation,
                        subject_kind: result.subject_kind,
                        subject_id: result.subject_id,
                        backend_id: optional_string(arguments, "backend_id"),
                        source_uri,
                        job_id: optional_string(arguments, "job_id"),
                        bytes_transferred: optional_u64(arguments, "bytes_transferred"),
                        hardware_profile: Some(format!(
                            "latency_ms={}",
                            started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                        )),
                        success: true,
                        error_class: None,
                    };
                    emit_success_receipt(
                        service,
                        session_id,
                        step_index,
                        &workload_id,
                        WorkloadReceipt::ModelLifecycle(receipt),
                    );
                    no_visual(true, Some(history_entry), None)
                }
                Err(error) => {
                    let (error_message, error_class) =
                        runtime_tool_failure(tool_name, &error.to_string());
                    let receipt = WorkloadModelLifecycleReceipt {
                        tool_name: tool_name.to_string(),
                        operation: descriptor.operation,
                        subject_kind: descriptor.subject_kind,
                        subject_id: model_id_for_receipt,
                        backend_id: optional_string(arguments, "backend_id"),
                        source_uri,
                        job_id: optional_string(arguments, "job_id"),
                        bytes_transferred: optional_u64(arguments, "bytes_transferred"),
                        hardware_profile: optional_string(arguments, "hardware_profile"),
                        success: false,
                        error_class: Some(error_class),
                    };
                    emit_failure_receipt(
                        service,
                        session_id,
                        step_index,
                        &workload_id,
                        WorkloadReceipt::ModelLifecycle(receipt),
                    );
                    no_visual(false, None, Some(error_message))
                }
            }
        }
        RegistryExecutionMode::UnloadModel => {
            let model_id = optional_string(arguments, "model_id");
            let model_hash = match resolve_model_hash(arguments) {
                Ok(hash) => hash,
                Err(error) => {
                    let receipt = WorkloadModelLifecycleReceipt {
                        tool_name: tool_name.to_string(),
                        operation: descriptor.operation,
                        subject_kind: descriptor.subject_kind,
                        subject_id,
                        backend_id: optional_string(arguments, "backend_id"),
                        source_uri,
                        job_id: optional_string(arguments, "job_id"),
                        bytes_transferred: optional_u64(arguments, "bytes_transferred"),
                        hardware_profile: optional_string(arguments, "hardware_profile"),
                        success: false,
                        error_class: workload::extract_error_class(Some(&error)),
                    };
                    emit_failure_receipt(
                        service,
                        session_id,
                        step_index,
                        &workload_id,
                        WorkloadReceipt::ModelLifecycle(receipt),
                    );
                    return no_visual(false, None, Some(error));
                }
            };
            let model_id_for_receipt = model_id.clone().unwrap_or_else(|| hex::encode(model_hash));
            match service
                .reasoning_inference
                .unload_registered_model(ModelUnloadRequest {
                    model_hash,
                    model_id,
                })
                .await
            {
                Ok(result) => {
                    let history_entry = json!({
                        "operation": result.operation.as_label(),
                        "subject_kind": result.subject_kind.as_label(),
                        "subject_id": result.subject_id,
                    })
                    .to_string();
                    let receipt = WorkloadModelLifecycleReceipt {
                        tool_name: tool_name.to_string(),
                        operation: result.operation,
                        subject_kind: result.subject_kind,
                        subject_id: result.subject_id,
                        backend_id: optional_string(arguments, "backend_id"),
                        source_uri,
                        job_id: optional_string(arguments, "job_id"),
                        bytes_transferred: optional_u64(arguments, "bytes_transferred"),
                        hardware_profile: optional_string(arguments, "hardware_profile"),
                        success: true,
                        error_class: None,
                    };
                    emit_success_receipt(
                        service,
                        session_id,
                        step_index,
                        &workload_id,
                        WorkloadReceipt::ModelLifecycle(receipt),
                    );
                    no_visual(true, Some(history_entry), None)
                }
                Err(error) => {
                    let (error_message, error_class) =
                        runtime_tool_failure(tool_name, &error.to_string());
                    let receipt = WorkloadModelLifecycleReceipt {
                        tool_name: tool_name.to_string(),
                        operation: descriptor.operation,
                        subject_kind: descriptor.subject_kind,
                        subject_id: model_id_for_receipt,
                        backend_id: optional_string(arguments, "backend_id"),
                        source_uri,
                        job_id: optional_string(arguments, "job_id"),
                        bytes_transferred: optional_u64(arguments, "bytes_transferred"),
                        hardware_profile: optional_string(arguments, "hardware_profile"),
                        success: false,
                        error_class: Some(error_class),
                    };
                    emit_failure_receipt(
                        service,
                        session_id,
                        step_index,
                        &workload_id,
                        WorkloadReceipt::ModelLifecycle(receipt),
                    );
                    no_visual(false, None, Some(error_message))
                }
            }
        }
        RegistryExecutionMode::ControlPlaneAccepted => {
            let job_id = optional_string(arguments, "job_id").unwrap_or_else(|| {
                control_plane_job_id(
                    session_id,
                    step_index,
                    tool_name,
                    descriptor.subject_kind,
                    &subject_id,
                    source_uri.as_deref(),
                )
            });
            let history_entry = json!({
                "operation": descriptor.operation.as_label(),
                "subject_kind": descriptor.subject_kind.as_label(),
                "subject_id": subject_id,
                "job_id": job_id,
                "status": "accepted",
                "source_uri": source_uri,
                "backend_id": optional_string(arguments, "backend_id"),
            })
            .to_string();
            let receipt = WorkloadModelLifecycleReceipt {
                tool_name: tool_name.to_string(),
                operation: descriptor.operation,
                subject_kind: descriptor.subject_kind,
                subject_id,
                backend_id: optional_string(arguments, "backend_id"),
                source_uri,
                job_id: Some(job_id),
                bytes_transferred: optional_u64(arguments, "bytes_transferred"),
                hardware_profile: optional_string(arguments, "hardware_profile"),
                success: true,
                error_class: None,
            };
            emit_success_receipt(
                service,
                session_id,
                step_index,
                &workload_id,
                WorkloadReceipt::ModelLifecycle(receipt),
            );
            no_visual(true, Some(history_entry), None)
        }
    }
}

async fn compute_native_workload_id(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    tool_name: &str,
    preview_seed: &str,
) -> String {
    let scrubbed = match service.scrubber.scrub(preview_seed).await {
        Ok((scrubbed, _)) => scrubbed,
        Err(_) => workload::WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER.to_string(),
    };
    let (truncated, _) = truncate_chars(&scrubbed, RECEIPT_TEXT_MAX_CHARS);
    let preview = if truncated.trim().is_empty() {
        tool_name.to_string()
    } else {
        format!("{tool_name} {truncated}")
    };
    let (preview, _) = truncate_chars(&preview, RECEIPT_PREVIEW_MAX_CHARS);
    workload::compute_workload_id(session_id, step_index, tool_name, &preview)
}

fn emit_activity(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    workload_id: &str,
    phase: &str,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };
    workload::emit_workload_activity(
        tx,
        session_id,
        step_index,
        workload_id.to_string(),
        WorkloadActivityKind::Lifecycle {
            phase: phase.to_string(),
            exit_code: None,
        },
    );
}

fn emit_success_receipt(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    workload_id: &str,
    receipt: WorkloadReceipt,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };
    emit_activity(service, session_id, step_index, workload_id, "completed");
    workload::emit_workload_receipt(tx, session_id, step_index, workload_id.to_string(), receipt);
}

fn emit_failure_receipt(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    workload_id: &str,
    receipt: WorkloadReceipt,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };
    emit_activity(service, session_id, step_index, workload_id, "failed");
    workload::emit_workload_receipt(tx, session_id, step_index, workload_id.to_string(), receipt);
}

fn build_text_generation_request(
    arguments: &Value,
    model_hash: [u8; 32],
    model_id: Option<String>,
) -> Result<TextGenerationRequest, String> {
    let input_context = serialize_text_generation_input(arguments)?;
    Ok(TextGenerationRequest {
        model_hash,
        model_id,
        input_context,
        options: inference_options_from_arguments(arguments),
        stream: optional_bool(arguments, "stream").unwrap_or(false),
    })
}

fn inference_options_from_arguments(arguments: &Value) -> InferenceOptions {
    InferenceOptions {
        tools: Vec::new(),
        temperature: optional_f32(arguments, "temperature").unwrap_or(0.0),
        json_mode: optional_bool(arguments, "json_mode").unwrap_or(false),
        max_tokens: optional_u32(arguments, "max_tokens").unwrap_or(512),
        ..Default::default()
    }
}

fn serialize_text_generation_input(arguments: &Value) -> Result<Vec<u8>, String> {
    if let Some(prompt) = optional_string(arguments, "prompt") {
        if !prompt.trim().is_empty() {
            return Ok(prompt.into_bytes());
        }
    }
    if let Some(text) = optional_string(arguments, "text") {
        if !text.trim().is_empty() {
            return Ok(text.into_bytes());
        }
    }
    if let Some(input) = arguments.get("input") {
        return serialize_inference_input_value(input);
    }
    if let Some(messages) = arguments.get("messages") {
        return serde_jcs::to_vec(messages).map_err(|error| {
            invalid_arguments_error(
                "model__responses",
                format!("failed to canonicalize 'messages': {}", error),
            )
        });
    }
    if let Some(context) = arguments.get("context") {
        return serialize_inference_input_value(context);
    }
    Err(invalid_arguments_error(
        "model__responses",
        "requires one of 'prompt', 'text', 'input', 'messages', or 'context'.",
    ))
}

fn serialize_inference_input_value(value: &Value) -> Result<Vec<u8>, String> {
    if let Some(text) = value.as_str() {
        return Ok(text.as_bytes().to_vec());
    }
    serde_jcs::to_vec(value).map_err(|error| {
        invalid_arguments_error(
            "model__responses",
            format!("failed to canonicalize inference input: {}", error),
        )
    })
}

fn text_embedding_input(arguments: &Value) -> Option<String> {
    optional_string(arguments, "text")
        .or_else(|| optional_string(arguments, "input"))
        .or_else(|| optional_string(arguments, "prompt"))
        .filter(|value| !value.trim().is_empty())
}

fn image_bytes_argument(arguments: &Value, tool_name: &str) -> Option<Result<Vec<u8>, String>> {
    let base64_value = optional_string(arguments, "image_base64")
        .or_else(|| optional_string(arguments, "image_bytes_base64"));
    if let Some(raw) = base64_value {
        return Some(BASE64_STANDARD.decode(raw.trim()).map_err(|error| {
            invalid_arguments_error(
                tool_name,
                format!("invalid base64 image payload: {}", error),
            )
        }));
    }
    let Some(values) = arguments.get("image_bytes").and_then(Value::as_array) else {
        return None;
    };
    Some(
        values
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|entry| u8::try_from(entry).ok())
                    .ok_or_else(|| {
                        invalid_arguments_error(
                            tool_name,
                            "image_bytes must be an array of byte values (0-255).",
                        )
                    })
            })
            .collect(),
    )
}

fn audio_bytes_argument(arguments: &Value, tool_name: &str) -> Result<Vec<u8>, String> {
    match base64_or_byte_array_argument(
        arguments,
        "audio_base64",
        "audio_bytes",
        tool_name,
        "audio",
    ) {
        Some(Ok(bytes)) => Ok(bytes),
        Some(Err(error)) => Err(error),
        None => Err(invalid_arguments_error(
            tool_name,
            "requires an audio payload in 'audio_base64' or 'audio_bytes'.",
        )),
    }
}

fn base64_or_byte_array_argument(
    arguments: &Value,
    base64_key: &str,
    bytes_key: &str,
    tool_name: &str,
    label: &str,
) -> Option<Result<Vec<u8>, String>> {
    if let Some(raw) = optional_string(arguments, base64_key) {
        return Some(BASE64_STANDARD.decode(raw.trim()).map_err(|error| {
            invalid_arguments_error(
                tool_name,
                format!("invalid base64 {} payload: {}", label, error),
            )
        }));
    }

    byte_array_argument(arguments, bytes_key, tool_name, label)
}

fn byte_array_argument(
    arguments: &Value,
    key: &str,
    tool_name: &str,
    label: &str,
) -> Option<Result<Vec<u8>, String>> {
    let values = arguments.get(key).and_then(Value::as_array)?;
    Some(
        values
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|entry| u8::try_from(entry).ok())
                    .ok_or_else(|| {
                        invalid_arguments_error(
                            tool_name,
                            format!(
                                "{} '{}' must be an array of byte values (0-255).",
                                label, key
                            ),
                        )
                    })
            })
            .collect(),
    )
}

fn required_binary_argument(
    candidate: Option<Result<Vec<u8>, String>>,
    tool_name: &str,
    detail: &str,
) -> Result<Vec<u8>, String> {
    match candidate {
        Some(Ok(bytes)) => Ok(bytes),
        Some(Err(error)) => Err(error),
        None => Err(invalid_arguments_error(tool_name, detail)),
    }
}

fn resolve_model_hash(arguments: &Value) -> Result<[u8; 32], String> {
    if let Some(raw_hash) = optional_string(arguments, "model_hash") {
        return decode_hex_hash("model_hash", &raw_hash);
    }
    if let Some(model_id) = optional_string(arguments, "model_id") {
        let digest = sha256(format!("model_id:{model_id}").as_bytes()).map_err(|error| {
            invalid_arguments_error(
                "model",
                format!("failed to derive model hash from model_id: {}", error),
            )
        })?;
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        return Ok(out);
    }
    Ok([0u8; 32])
}

fn decode_hex_hash(field: &str, raw_hash: &str) -> Result<[u8; 32], String> {
    let decoded = hex::decode(raw_hash.trim()).map_err(|error| {
        invalid_arguments_error(
            "model",
            format!("invalid hex value for '{}': {}", field, error),
        )
    })?;
    if decoded.len() != 32 {
        return Err(invalid_arguments_error(
            "model",
            format!(
                "'{}' must decode to 32 bytes (got {}).",
                field,
                decoded.len()
            ),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn registry_load_path(arguments: &Value) -> Option<PathBuf> {
    optional_string(arguments, "path")
        .or_else(|| optional_string(arguments, "artifact_path"))
        .or_else(|| optional_string(arguments, "source_uri"))
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
}

fn registry_source_uri(arguments: &Value) -> Option<String> {
    optional_string(arguments, "source_uri")
        .or_else(|| optional_string(arguments, "artifact_url"))
        .or_else(|| optional_string(arguments, "download_url"))
}

fn registry_subject_id(
    arguments: &Value,
    subject_kind: RegistrySubjectKind,
    fallback: &str,
) -> String {
    let candidate = match subject_kind {
        RegistrySubjectKind::Model => optional_string(arguments, "model_id")
            .or_else(|| optional_string(arguments, "subject_id"))
            .or_else(|| optional_string(arguments, "path"))
            .or_else(|| registry_source_uri(arguments)),
        RegistrySubjectKind::Backend => optional_string(arguments, "backend_id")
            .or_else(|| optional_string(arguments, "subject_id")),
        RegistrySubjectKind::Gallery => optional_string(arguments, "gallery_id")
            .or_else(|| optional_string(arguments, "subject_id"))
            .or_else(|| registry_source_uri(arguments)),
        RegistrySubjectKind::InstallJob => optional_string(arguments, "job_id")
            .or_else(|| optional_string(arguments, "subject_id")),
    };
    candidate
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn preview_text_argument(arguments: &Value) -> Option<String> {
    optional_string(arguments, "prompt")
        .or_else(|| optional_string(arguments, "text"))
        .or_else(|| optional_string(arguments, "query"))
        .or_else(|| optional_string(arguments, "input"))
        .or_else(|| optional_string(arguments, "source_uri"))
        .or_else(|| optional_string(arguments, "backend_id"))
        .or_else(|| optional_string(arguments, "model_id"))
        .or_else(|| registry_source_uri(arguments))
}

fn string_array_argument(arguments: &Value, key: &str) -> Result<Vec<String>, String> {
    let values = arguments
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_arguments_error(
                "model__rerank",
                format!("'{}' must be an array of strings.", key),
            )
        })?;

    values
        .iter()
        .map(|value| {
            value.as_str().map(ToString::to_string).ok_or_else(|| {
                invalid_arguments_error(
                    "model__rerank",
                    format!("'{}' must contain only strings.", key),
                )
            })
        })
        .collect()
}

fn optional_string(arguments: &Value, key: &str) -> Option<String> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn required_string_argument(
    arguments: &Value,
    key: &str,
    tool_name: &str,
) -> Result<String, String> {
    optional_string(arguments, key)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            invalid_arguments_error(tool_name, format!("requires a non-empty '{}'.", key))
        })
}

fn optional_bool(arguments: &Value, key: &str) -> Option<bool> {
    arguments.get(key).and_then(Value::as_bool)
}

fn optional_u32(arguments: &Value, key: &str) -> Option<u32> {
    arguments
        .get(key)
        .and_then(Value::as_u64)
        .map(|value| value.min(u64::from(u32::MAX)) as u32)
}

fn optional_u64(arguments: &Value, key: &str) -> Option<u64> {
    arguments.get(key).and_then(Value::as_u64)
}

fn optional_f32(arguments: &Value, key: &str) -> Option<f32> {
    arguments
        .get(key)
        .and_then(Value::as_f64)
        .map(|value| value as f32)
}

fn dynamic_tool_name(dynamic_tool: &Value) -> Option<&str> {
    dynamic_tool.get("name").and_then(Value::as_str)
}

fn dynamic_tool_arguments(dynamic_tool: &Value) -> &Value {
    dynamic_tool.get("arguments").unwrap_or(&Value::Null)
}

fn truncate_chars(input: &str, max: usize) -> (String, bool) {
    if max == 0 {
        return (String::new(), !input.is_empty());
    }
    let mut out = String::new();
    let mut count = 0usize;
    for ch in input.chars() {
        if count >= max {
            return (out, true);
        }
        out.push(ch);
        count += 1;
    }
    (out, false)
}

fn invalid_arguments_error(tool_name: &str, detail: impl Into<String>) -> String {
    format!(
        "ERROR_CLASS=InvalidArguments {}",
        format_tool_error(tool_name, detail)
    )
}

fn unsupported_tool_error(tool_name: &str, detail: impl Into<String>) -> String {
    format!(
        "ERROR_CLASS=UnsupportedTool {}",
        format_tool_error(tool_name, detail)
    )
}

fn runtime_tool_failure(tool_name: &str, detail: &str) -> (String, String) {
    let error_class = if detail
        .to_ascii_lowercase()
        .contains("not supported by this runtime")
    {
        "ToolUnavailable"
    } else {
        "RuntimeExecutionFailed"
    };
    (
        format!(
            "ERROR_CLASS={} {}",
            error_class,
            format_tool_error(tool_name, detail)
        ),
        error_class.to_string(),
    )
}

fn format_tool_error(tool_name: &str, detail: impl Into<String>) -> String {
    format!("{} {}", tool_name, detail.into())
}

fn control_plane_job_id(
    session_id: [u8; 32],
    step_index: u32,
    tool_name: &str,
    subject_kind: RegistrySubjectKind,
    subject_id: &str,
    source_uri: Option<&str>,
) -> String {
    let digest = sha256(
        format!(
            "{}:{}:{}:{}:{}:{}",
            hex::encode(session_id),
            step_index,
            tool_name,
            subject_kind.as_label(),
            subject_id,
            source_uri.unwrap_or_default()
        )
        .as_bytes(),
    )
    .unwrap_or_else(|_| [0u8; 32]);
    format!("job_{}", hex::encode(&digest[..8]))
}
