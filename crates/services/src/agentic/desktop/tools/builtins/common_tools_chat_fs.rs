{
    // Common Tools (Chat, FS)
    let chat_params = json!({
        "type": "object",
        "properties": {
            "message": { "type": "string", "description": "The response text to show to the user." }
        },
        "required": ["message"]
    });
    tools.push(LlmToolDefinition {
        name: "chat__reply".to_string(),
        description: "Send a text message or answer to the user. WARNING: This PAUSES execution to wait for user input. Do not use for intermediate status updates.".to_string(),
        parameters: chat_params.to_string(),
    });

    let await_params = json!({
        "type": "object",
        "properties": {
            "child_session_id_hex": { "type": "string" }
        },
        "required": ["child_session_id_hex"]
    });
    tools.push(LlmToolDefinition {
        name: "agent__await_result".to_string(),
        description:
            "Check whether a delegated child worker has completed its bounded task. Returns 'Running' if not finished, otherwise returns the worker handoff rendered through its deterministic merge contract."
                .to_string(),
        parameters: await_params.to_string(),
    });

    let pause_params = json!({
        "type": "object",
        "properties": {
            "reason": { "type": "string" }
        },
        "required": ["reason"]
    });
    tools.push(LlmToolDefinition {
        name: "agent__pause".to_string(),
        description: "Pause execution to wait for user input or long-running tasks.".to_string(),
        parameters: pause_params.to_string(),
    });

    let complete_params = json!({
        "type": "object",
        "properties": {
            "result": { "type": "string", "description": "The final result or summary of the completed task." }
        },
        "required": ["result"]
    });
    tools.push(LlmToolDefinition {
        name: "agent__complete".to_string(),
        description:
            "Call this when you have successfully achieved the goal to finish the session."
                .to_string(),
        parameters: complete_params.to_string(),
    });

    let checkout_params = json!({
        "type": "object",
        "properties": {
            "merchant_url": { "type": "string" },
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "quantity": { "type": "integer" }
                    }
                }
            },
            "total_amount": { "type": "number", "description": "Total amount to authorize" },
            "currency": { "type": "string" },
            "buyer_email": { "type": "string" }
        },
        "required": ["merchant_url", "items", "total_amount", "currency"]
    });
    tools.push(LlmToolDefinition {
        name: "commerce__checkout".to_string(),
        description:
            "Purchase items from a UCP-compatible merchant using secure payment injection."
                .to_string(),
        parameters: checkout_params.to_string(),
    });

    let fs_write_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Absolute path to write the file to" },
            "content": { "type": "string", "description": "Text content to write, or replacement content for a specific line when line_number is set" },
            "line_number": {
                "type": "integer",
                "minimum": 1,
                "description": "Optional 1-based line index to edit atomically. When omitted, writes the full file content."
            }
        },
        "required": ["path", "content"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__write_file".to_string(),
        description: "Write full text content to a file, or edit a single line deterministically by setting line_number. Prefer this when the change is tiny or an exact filesystem__patch search block would be awkward to encode."
            .to_string(),
        parameters: fs_write_params.to_string(),
    });

    let fs_edit_line_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Absolute path to the file to edit" },
            "line_number": {
                "type": "integer",
                "minimum": 1,
                "description": "1-based line index to replace."
            },
            "content": { "type": "string", "description": "Replacement content for the target line." }
        },
        "required": ["path", "line_number", "content"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__edit_line".to_string(),
        description: "Deterministically replace exactly one line in a file (alias of filesystem__write_file with line_number). Prefer this for single-line code fixes instead of a brittle filesystem__patch block.".to_string(),
        parameters: fs_edit_line_params.to_string(),
    });

    let fs_patch_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Absolute path to the file to patch" },
            "search": {
                "type": "string",
                "description": "Exact string block to replace. Must match exactly one occurrence."
            },
            "replace": { "type": "string", "description": "Replacement content for the matched block" }
        },
        "required": ["path", "search", "replace"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__patch".to_string(),
        description:
            "Replace a unique text block in a file. Copy the search block exactly from the latest read, including newlines and indentation; this fails if the search block is missing or ambiguous. For one-line or escape-heavy edits, prefer filesystem__edit_line or filesystem__write_file."
                .to_string(),
        parameters: fs_patch_params.to_string(),
    });

    let fs_read_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Absolute path to read" }
        },
        "required": ["path"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__read_file".to_string(),
        description: "Read exact text content from a file, preserving newlines so the result can be reused directly in filesystem__patch search blocks.".to_string(),
        parameters: fs_read_params.to_string(),
    });

    let fs_ls_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Directory path to list" }
        },
        "required": ["path"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__list_directory".to_string(),
        description: "List files and directories at a given path.".to_string(),
        parameters: fs_ls_params.to_string(),
    });

    let fs_search_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Root directory to search in" },
            "regex": { "type": "string", "description": "Rust regex pattern to find in file content" },
            "file_pattern": { "type": "string", "description": "Optional glob pattern to filter file names (e.g. '*.rs')" }
        },
        "required": ["path", "regex"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__search".to_string(),
        description:
            "Recursively search for a valid Rust regex pattern in files under a directory and return matching lines. Use this only when the exact file path is still unknown; if you already know the file, read it directly."
                .to_string(),
        parameters: fs_search_params.to_string(),
    });

    let fs_stat_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Path to inspect for deterministic metadata." }
        },
        "required": ["path"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__stat".to_string(),
        description:
            "Return deterministic metadata for a file or directory, including modified timestamp."
                .to_string(),
        parameters: fs_stat_params.to_string(),
    });

    let fs_move_params = json!({
        "type": "object",
        "properties": {
            "source_path": { "type": "string", "description": "Source path to move or rename." },
            "destination_path": { "type": "string", "description": "Destination path." },
            "overwrite": {
                "type": "boolean",
                "description": "When true, replace an existing destination path."
            }
        },
        "required": ["source_path", "destination_path"]
    });
    let fs_copy_params = json!({
        "type": "object",
        "properties": {
            "source_path": { "type": "string", "description": "Source path to copy." },
            "destination_path": { "type": "string", "description": "Destination path." },
            "overwrite": {
                "type": "boolean",
                "description": "When true, replace an existing destination path."
            }
        },
        "required": ["source_path", "destination_path"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__copy_path".to_string(),
        description: "Copy a file/directory deterministically without invoking shell commands."
            .to_string(),
        parameters: fs_copy_params.to_string(),
    });

    tools.push(LlmToolDefinition {
        name: "filesystem__move_path".to_string(),
        description:
            "Move or rename a file/directory deterministically without invoking shell commands."
                .to_string(),
        parameters: fs_move_params.to_string(),
    });

    let fs_delete_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Path to delete." },
            "recursive": {
                "type": "boolean",
                "description": "When true, delete directories recursively."
            },
            "ignore_missing": {
                "type": "boolean",
                "description": "When true, treat missing paths as success."
            }
        },
        "required": ["path"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__delete_path".to_string(),
        description:
            "Delete a file/symlink, or a directory when recursive=true, using deterministic filesystem APIs."
                .to_string(),
        parameters: fs_delete_params.to_string(),
    });

    let fs_create_directory_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Directory path to create." },
            "recursive": {
                "type": "boolean",
                "description": "When true, create missing parent directories as needed."
            }
        },
        "required": ["path"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__create_directory".to_string(),
        description: "Create a directory deterministically without invoking shell commands."
            .to_string(),
        parameters: fs_create_directory_params.to_string(),
    });

    let fs_create_zip_params = json!({
        "type": "object",
        "properties": {
            "source_path": { "type": "string", "description": "Source directory path to compress." },
            "destination_zip_path": { "type": "string", "description": "Destination .zip file path." },
            "overwrite": {
                "type": "boolean",
                "description": "When true, replace an existing destination zip file."
            }
        },
        "required": ["source_path", "destination_zip_path"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__create_zip".to_string(),
        description:
            "Create a zip archive from a source directory deterministically without invoking shell commands."
                .to_string(),
        parameters: fs_create_zip_params.to_string(),
    });

    let install_pkg_params = json!({
        "type": "object",
        "properties": {
            "package": {
                "type": "string",
                "description": "Package name or identifier to install (e.g. 'pydantic', '@scope/pkg', 'ripgrep')."
            },
            "manager": {
                "type": "string",
                "enum": ["apt-get", "brew", "pip", "npm", "pnpm", "cargo", "winget", "choco", "yum", "dnf"],
                "description": "Optional package manager. If omitted, platform default is used (Linux: apt-get, macOS: brew, Windows: winget)."
            }
        },
        "required": ["package"]
    });
    tools.push(LlmToolDefinition {
        name: "sys__install_package".to_string(),
        description: "Install a dependency via a deterministic manager mapping. Prefer this over raw sys__exec for package installs."
            .to_string(),
        parameters: install_pkg_params.to_string(),
    });
}
