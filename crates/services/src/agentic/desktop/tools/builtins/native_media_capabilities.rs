{
    let allow_media_transcription =
        is_tool_allowed_for_resolution(resolved_intent, "media__transcribe_audio");
    let allow_media_synthesis =
        is_tool_allowed_for_resolution(resolved_intent, "media__synthesize_speech");
    let allow_media_vision = is_tool_allowed_for_resolution(resolved_intent, "media__vision_read");
    let allow_media_image_generation =
        is_tool_allowed_for_resolution(resolved_intent, "media__generate_image")
            || is_tool_allowed_for_resolution(resolved_intent, "media__edit_image");
    let allow_media_video_generation =
        is_tool_allowed_for_resolution(resolved_intent, "media__generate_video");

    if allow_media_transcription {
        let transcription_params = json!({
            "type": "object",
            "properties": {
                "audio_base64": {
                    "type": "string",
                    "description": "Base64-encoded audio payload to transcribe."
                },
                "audio_bytes": {
                    "type": "array",
                    "description": "Optional byte-array audio payload when base64 is inconvenient.",
                    "items": { "type": "integer" }
                },
                "mime_type": {
                    "type": "string",
                    "description": "MIME type for the encoded audio payload such as audio/wav or audio/mpeg."
                },
                "language": {
                    "type": "string",
                    "description": "Optional language hint for transcription."
                },
                "model_id": {
                    "type": "string",
                    "description": "Optional model identifier to force a specific local transcription model."
                }
            },
            "required": ["mime_type"]
        });
        tools.push(LlmToolDefinition {
            name: "media__transcribe_audio".to_string(),
            description:
                "Transcribe a local audio artifact through the kernel-native media substrate and return typed transcript metadata."
                    .to_string(),
            parameters: transcription_params.to_string(),
        });
    }

    if allow_media_synthesis {
        let speech_params = json!({
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text to synthesize into speech."
                },
                "voice": {
                    "type": "string",
                    "description": "Optional voice identifier."
                },
                "mime_type": {
                    "type": "string",
                    "description": "Optional preferred output MIME type such as audio/wav."
                },
                "model_id": {
                    "type": "string",
                    "description": "Optional model identifier to force a specific local synthesis model."
                }
            },
            "required": ["text"]
        });
        tools.push(LlmToolDefinition {
            name: "media__synthesize_speech".to_string(),
            description:
                "Generate a speech artifact from text inside the kernel media runtime instead of routing through shell commands or external services."
                    .to_string(),
            parameters: speech_params.to_string(),
        });
    }

    if allow_media_vision {
        let vision_params = json!({
            "type": "object",
            "properties": {
                "image_base64": {
                    "type": "string",
                    "description": "Base64-encoded image payload to inspect."
                },
                "image_bytes": {
                    "type": "array",
                    "description": "Optional byte-array image payload when base64 is inconvenient.",
                    "items": { "type": "integer" }
                },
                "mime_type": {
                    "type": "string",
                    "description": "MIME type for the encoded image payload."
                },
                "prompt": {
                    "type": "string",
                    "description": "Optional question or instruction bound to the image."
                },
                "model_id": {
                    "type": "string",
                    "description": "Optional model identifier to force a specific local vision model."
                }
            }
        });
        tools.push(LlmToolDefinition {
            name: "media__vision_read".to_string(),
            description:
                "Inspect an image or screenshot with the kernel-native multimodal runtime and return structured text output."
                    .to_string(),
            parameters: vision_params.to_string(),
        });
    }

    if allow_media_image_generation {
        let image_generation_params = json!({
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "Prompt used to generate an image."
                },
                "mime_type": {
                    "type": "string",
                    "description": "Optional preferred output MIME type such as image/png."
                },
                "model_id": {
                    "type": "string",
                    "description": "Optional model identifier to force a specific local image model."
                }
            },
            "required": ["prompt"]
        });
        tools.push(LlmToolDefinition {
            name: "media__generate_image".to_string(),
            description:
                "Generate an image artifact through the absorbed kernel media runtime."
                    .to_string(),
            parameters: image_generation_params.to_string(),
        });

        let image_edit_params = json!({
            "type": "object",
            "properties": {
                "source_image_base64": {
                    "type": "string",
                    "description": "Base64-encoded source image to edit."
                },
                "source_image_bytes": {
                    "type": "array",
                    "description": "Optional byte-array source image payload.",
                    "items": { "type": "integer" }
                },
                "source_mime_type": {
                    "type": "string",
                    "description": "MIME type for the source image."
                },
                "prompt": {
                    "type": "string",
                    "description": "Optional edit instruction or inpainting prompt."
                },
                "mask_image_base64": {
                    "type": "string",
                    "description": "Optional base64-encoded mask image."
                },
                "mask_image_bytes": {
                    "type": "array",
                    "description": "Optional byte-array mask image payload.",
                    "items": { "type": "integer" }
                },
                "model_id": {
                    "type": "string",
                    "description": "Optional model identifier to force a specific local image editing model."
                }
            },
            "required": ["source_mime_type"]
        });
        tools.push(LlmToolDefinition {
            name: "media__edit_image".to_string(),
            description:
                "Edit or inpaint an existing image artifact through the kernel media runtime."
                    .to_string(),
            parameters: image_edit_params.to_string(),
        });
    }

    if allow_media_video_generation {
        let video_generation_params = json!({
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "Prompt used to generate a video."
                },
                "mime_type": {
                    "type": "string",
                    "description": "Optional preferred output MIME type such as video/mp4."
                },
                "duration_ms": {
                    "type": "integer",
                    "description": "Optional requested output duration in milliseconds."
                },
                "model_id": {
                    "type": "string",
                    "description": "Optional model identifier to force a specific local video model."
                }
            },
            "required": ["prompt"]
        });
        tools.push(LlmToolDefinition {
            name: "media__generate_video".to_string(),
            description:
                "Generate a video artifact through the absorbed kernel media runtime."
                    .to_string(),
            parameters: video_generation_params.to_string(),
        });
    }
}
