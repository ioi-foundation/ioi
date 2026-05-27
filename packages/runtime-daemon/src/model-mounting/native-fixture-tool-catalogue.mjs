const PIXEL_PNG_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=";

function extractMarker(text, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const matches = Array.from(String(text || "").matchAll(new RegExp(`${escaped}=([^\\s]+)`, "gi")));
  return matches.at(-1)?.[1] ?? "";
}

function extractFirstMarker(text, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return String(text || "").match(new RegExp(`${escaped}=([^\\s]+)`, "i"))?.[1] ?? "";
}

function commandIdFromText(text) {
  const raw = String(text || "");
  const candidates = [
    ...Array.from(raw.matchAll(/"command_id"\s*:\s*"([^"]+)"/gi), (match) => match[1]),
    ...Array.from(raw.matchAll(/\\"command_id\\"\s*:\s*\\"([^"\\]+)\\"/gi), (match) => match[1]),
    ...Array.from(raw.matchAll(/"commandId"\s*:\s*"([^"]+)"/gi), (match) => match[1]),
    ...Array.from(raw.matchAll(/\\"commandId\\"\s*:\s*\\"([^"\\]+)\\"/gi), (match) => match[1]),
    ...Array.from(raw.matchAll(/\bcommand_id[=:]\s*([A-Za-z0-9_.:-]+)/gi), (match) => match[1]),
  ];
  return (
    candidates.findLast((candidate) => /^shell__(?:start|run):[A-Fa-f0-9]{64}$/.test(candidate)) ??
    candidates.findLast((candidate) => /^[A-Za-z0-9_.:-]{1,160}$/.test(candidate)) ??
    "toolcat-missing-command-id"
  );
}

function childSessionIdFromText(text) {
  const raw = String(text || "");
  const candidates = [
    ...Array.from(raw.matchAll(/\bchild_session_id_hex[=:]\s*([A-Fa-f0-9]{16,64})/gi), (match) => match[1]),
    ...Array.from(raw.matchAll(/"child_session_id_hex"\s*:\s*"([A-Fa-f0-9]{16,64})"/gi), (match) => match[1]),
    ...Array.from(raw.matchAll(/\\"child_session_id_hex\\"\s*:\s*\\"([A-Fa-f0-9]{16,64})\\"/gi), (match) => match[1]),
  ];
  return candidates.findLast((candidate) => !/^0+$/.test(candidate)) ?? "";
}

function tabIdFromText(text) {
  const raw = String(text || "");
  return (
    raw.match(/"tab_id"\s*:\s*"([^"]+)"/i)?.[1] ??
    raw.match(/"tabId"\s*:\s*"([^"]+)"/i)?.[1] ??
    raw.match(/\btab_id[=:]\s*([A-Za-z0-9_.:-]+)/i)?.[1] ??
    "toolcat-missing-tab-id"
  );
}

function memoryFrameIdFromText(text) {
  const raw = String(text || "");
  const candidates = [
    ...Array.from(raw.matchAll(/\[ID:(\d+)\]/gi), (match) => Number(match[1])),
    ...Array.from(raw.matchAll(/"frame_id"\s*:\s*(\d+)/gi), (match) => Number(match[1])),
    ...Array.from(raw.matchAll(/\bframe_id[=:]\s*(\d+)/gi), (match) => Number(match[1])),
  ].filter((value) => Number.isSafeInteger(value) && value > 0);
  return candidates.at(-1) ?? 1;
}

function done(name, called, failed) {
  return called(name) || failed(name);
}

function runChain({ steps, called, failed, jsonTool }) {
  const next = steps.find((step) => {
    if (typeof step.ready === "function") return !step.ready();
    return !done(step.name, called, failed);
  });
  if (!next) return null;
  const args = typeof next.args === "function" ? next.args() : next.args;
  return jsonTool(next.name, args ?? {});
}

function finalSteps(message) {
  return [
    { name: "chat__reply", args: { message } },
    { name: "agent__complete", args: { result: message } },
  ];
}

const BROWSER_FIXTURE_NAVIGATION_TOOLS = new Set([
  "browser__inspect",
  "browser__find_text",
  "browser__screenshot",
  "browser__list_options",
  "browser__select_option",
  "browser__click",
  "browser__type",
  "browser__press_key",
  "browser__select",
  "browser__copy",
  "browser__paste",
  "browser__wait",
  "browser__upload",
  "browser__list_tabs",
  "browser__switch_tab",
  "browser__close_tab",
  "browser__inspect_canvas",
  "browser__hover",
  "browser__move_pointer",
  "browser__pointer_down",
  "browser__pointer_up",
  "browser__click_at",
  "browser__scroll",
  "browser__subagent",
]);

function browserFixtureSetupSteps(toolName, surface) {
  const browserUrl = extractMarker(surface, "browser_fixture_url");
  const secondUrl = extractMarker(surface, "browser_fixture_second_url");
  const steps = [];

  if (toolName === "browser__back") {
    steps.push({ name: "browser__navigate", args: { url: secondUrl || browserUrl } });
    return steps;
  }

  if (BROWSER_FIXTURE_NAVIGATION_TOOLS.has(toolName)) {
    steps.push({ name: "browser__navigate", args: { url: browserUrl || secondUrl } });
  }

  if (toolName === "browser__click_at") {
    steps.push({ name: "browser__inspect", args: {} });
  }

  if (toolName === "browser__copy") {
    steps.push({ name: "browser__select", args: singleToolArgs("browser__select", surface) });
  }

  if (toolName === "browser__paste") {
    steps.push({ name: "clipboard__copy", args: singleToolArgs("clipboard__copy", surface) });
  }

  if (toolName === "browser__pointer_down" || toolName === "browser__pointer_up") {
    steps.push({ name: "browser__move_pointer", args: singleToolArgs("browser__move_pointer", surface) });
  }

  if (toolName === "browser__pointer_up") {
    steps.push({ name: "browser__pointer_down", args: singleToolArgs("browser__pointer_down", surface) });
  }

  if (toolName === "browser__switch_tab" || toolName === "browser__close_tab") {
    steps.push({ name: "browser__list_tabs", args: singleToolArgs("browser__list_tabs", surface) });
  }

  return steps;
}

function workspacePaths(surface) {
  const root = extractMarker(surface, "workspace_fixture_root");
  const readme = extractMarker(surface, "workspace_fixture_readme");
  const notes = extractMarker(surface, "workspace_fixture_notes");
  const editTarget = extractMarker(surface, "workspace_fixture_edit_target");
  const upload = extractMarker(surface, "workspace_fixture_upload");
  const model = extractMarker(surface, "workspace_fixture_model");
  const image = extractMarker(surface, "workspace_fixture_image");
  return {
    root,
    readme: readme || `${root}/readme.md`,
    notes: notes || `${root}/notes.txt`,
    editTarget: editTarget || `${root}/edit-target.txt`,
    upload: upload || `${root}/nested/upload.txt`,
    model: model || `${root}/models/toolcat-model.gguf`,
    image: image || `${root}/media/pixel.png`,
    scratchDir: `${root}/scratch`,
    writeTarget: `${root}/scratch/write-target.txt`,
    copyTarget: `${root}/scratch/copy-target.txt`,
    moveTarget: `${root}/scratch/moved-target.txt`,
    zipTarget: `${root}/archive.zip`,
  };
}

function singleToolArgs(toolName, surface, rawCurrentTurn = "") {
  const historyText = `${surface}\n${rawCurrentTurn}`;
  const paths = workspacePaths(surface);
  const browserUrl = extractMarker(surface, "browser_fixture_url");
  const statusUrl = extractMarker(surface, "browser_fixture_status_url");
  const secondUrl = extractMarker(surface, "browser_fixture_second_url");
  const mediaUrl = extractMarker(surface, "browser_fixture_media_url");
  const providersUrl = extractMarker(surface, "computer_use_providers_url");
  const modelId = "toolcat/live-fixture-model";
  const backendId = "backend.toolcat.fixture";
  switch (toolName) {
    case "chat__reply":
      return { message: "TOOLCAT_SINGLE_TOOL chat__reply live IDE probe completed." };
    case "agent__complete":
      return { result: "TOOLCAT_SINGLE_TOOL agent__complete live IDE probe completed." };
    case "agent__pause":
      return { reason: "TOOLCAT_SINGLE_TOOL controlled pause probe." };
    case "agent__escalate":
      return {
        reason: "TOOLCAT_SINGLE_TOOL controlled escalation probe.",
        missing_capability: "tool_catalogue_live_matrix.single_tool_probe",
      };
    case "agent__delegate":
      return {
        goal: "Return one sentence confirming the Rust Agent delegate tool row is reachable.",
        budget: 1,
        role: "verifier",
        success_criteria: "Delegate call is accepted or fails closed with a trace.",
      };
    case "agent__await":
      return {
        child_session_id_hex:
          childSessionIdFromText(historyText) ||
          "0000000000000000000000000000000000000000000000000000000000000000",
      };
    case "file__list":
      return { path: paths.root };
    case "file__info":
      return { path: paths.readme };
    case "file__read":
      return { path: paths.readme };
    case "file__view":
      return { path: paths.notes, start_line: 1, line_count: 4 };
    case "file__search":
      return { path: paths.root, regex: "TOOLCAT_CANARY", file_pattern: "*.txt" };
    case "file__create_dir":
      return { path: paths.scratchDir, recursive: true };
    case "file__write":
      return { path: paths.writeTarget, content: "first\nsecond\nthird\n" };
    case "file__edit":
      return { path: paths.editTarget, search: "line two", replace: "line two edited" };
    case "file__multi_edit":
      return {
        path: paths.editTarget,
        edits: [
          { search: "line one", replace: "line one edited" },
          { search: "line three", replace: "line three edited" },
        ],
      };
    case "file__copy":
      return { source_path: paths.readme, destination_path: paths.copyTarget, overwrite: true };
    case "file__move":
      return { source_path: paths.copyTarget, destination_path: paths.moveTarget, overwrite: true };
    case "file__zip":
      return { source_path: paths.scratchDir, destination_zip_path: paths.zipTarget, overwrite: true };
    case "file__delete":
      return { path: paths.moveTarget, ignore_missing: true };
    case "shell__cd":
      return { path: paths.root || "." };
    case "shell__run":
      return { command: "node", args: ["-e", "console.log('toolcat shell run ok')"] };
    case "shell__start":
      return {
        command: "node",
        args: ["-e", "process.stdin.resume(); process.stdin.on('data', d => { console.log('stdin:' + d.toString().trim()); });"],
        wait_ms_before_async: 100,
      };
    case "shell__status":
      return { command_id: commandIdFromText(historyText) };
    case "shell__input":
      return { command_id: commandIdFromText(historyText), stdin: "toolcat input\n" };
    case "shell__terminate":
      return { command_id: commandIdFromText(historyText) };
    case "shell__reset":
      return {};
    case "software_install__resolve":
      return {
        request: {
          target_text: "nonexistent-toolcat-fixture",
          target_kind: "command_line_tool",
          manager_preference: "apt-get",
          provenance: "live-ide-tool-catalogue-disposable-fixture",
        },
      };
    case "software_install__execute_plan":
      return { plan_ref: "toolcat-disposable-plan-ref" };
    case "web__search":
      return { query: "TOOLCAT local fixture verification", max_results: 1 };
    case "web__read":
      return { url: statusUrl || "https://example.com", max_chars: 1000 };
    case "http__fetch":
      return { url: statusUrl || browserUrl || "https://example.com", max_chars: 1000 };
    case "math__eval":
      return { expression: "(247 * 38) + 12" };
    case "model__embeddings":
      return { text: "TOOLCAT memory embedding fixture" };
    case "model__rerank":
      return {
        query: "tool catalogue memory fixture",
        candidates: ["browser matrix", "memory fixture", "model registry"],
        top_k: 2,
      };
    case "browser__navigate":
      return { url: browserUrl || secondUrl };
    case "browser__inspect":
      return {};
    case "browser__find_text":
      return { query: "TOOLCAT_BROWSER_CANARY", scope: "document", scroll: true };
    case "browser__screenshot":
      return { full_page: false };
    case "browser__list_options":
      return { selector: "#toolcat-select" };
    case "browser__select_option":
      return { selector: "#toolcat-select", value: "beta" };
    case "browser__click":
      return { selector: "#toolcat-input" };
    case "browser__type":
      return { selector: "#toolcat-input", text: "typed through browser__type" };
    case "browser__press_key":
      return { selector: "#toolcat-input", key: "a", modifiers: ["Control"] };
    case "browser__select":
      return { selector: "#fixture-copy", start_offset: 0, end_offset: 23 };
    case "browser__copy":
      return {};
    case "browser__paste":
      return { selector: "#toolcat-input" };
    case "browser__wait":
      return { condition: "text_present", query: "TOOLCAT_BROWSER_CANARY", scope: "document", timeout_ms: 3000 };
    case "browser__upload":
      return { paths: [paths.upload], selector: "#toolcat-file" };
    case "browser__back":
      return { steps: 1 };
    case "browser__list_tabs":
      return {};
    case "browser__switch_tab":
      return { tab_id: tabIdFromText(historyText) };
    case "browser__close_tab":
      return { tab_id: tabIdFromText(historyText) };
    case "browser__inspect_canvas":
      return { selector: "#toolcat-canvas" };
    case "browser__hover":
      return { selector: "#toolcat-button", duration_ms: 100 };
    case "browser__move_pointer":
      return { observation_ref: "toolcat-observation", coordinate_space_id: "viewport_css_px", semantic_id: "toolcat-canvas", x: 48, y: 48 };
    case "browser__pointer_down":
      return { button: "left" };
    case "browser__pointer_up":
      return { button: "left" };
    case "browser__click_at":
      return { id: "toolcat-canvas" };
    case "browser__scroll":
      return { delta_y: 180, delta_x: 0 };
    case "browser__subagent": {
      const targetUrl = browserUrl || "the current browser fixture page";
      return {
        task_name: "tool catalogue browser fixture",
        task_summary: "Verify browser subagent packaging reaches the fixture page.",
        recording_name: "toolcat-browser-subagent",
        task: `Use browser__navigate to open ${targetUrl}, then inspect the browser page and report the TOOLCAT_BROWSER_CANARY text without external actions.`,
      };
    }
    case "screen__inspect":
      return {};
    case "screen__find":
      return { query: "Connect Wallet" };
    case "screen__click":
      return { id: "btn-1" };
    case "screen__click_at":
      return { x: 200, y: 125 };
    case "screen__type":
      return { text: "toolcat desktop type probe" };
    case "screen__scroll":
      return { delta_y: 120, delta_x: 0 };
    case "screen":
      return { action: "screenshot" };
    case "window__focus":
      return { title: "Autopilot" };
    case "app__launch":
      return { app_name: "autopilot-nonexistent-toolcat-fixture" };
    case "clipboard__copy":
      return { content: "TOOLCAT_CLIPBOARD_CANARY" };
    case "clipboard__paste":
      return {};
    case "media__vision_read":
      return { image_base64: PIXEL_PNG_BASE64, mime_type: "image/png", prompt: "Describe this toolcat pixel fixture." };
    case "media__transcribe_audio":
      return { audio_base64: "", mime_type: "audio/wav", language: "en" };
    case "media__generate_image":
      return { prompt: "A tiny tool catalogue verification badge", mime_type: "image/png" };
    case "media__edit_image":
      return { source_image_base64: PIXEL_PNG_BASE64, source_mime_type: "image/png", prompt: "Add a small verification dot." };
    case "media__generate_video":
      return { prompt: "One second verification card", mime_type: "video/mp4", duration_ms: 1000 };
    case "media__synthesize_speech":
      return { text: "Tool catalogue verification", mime_type: "audio/wav" };
    case "media__extract_transcript":
      return { url: mediaUrl || statusUrl, language: "en", max_chars: 1000 };
    case "media__extract_evidence":
      return { url: mediaUrl || statusUrl, language: "en", max_chars: 1000, frame_limit: 1 };
    case "model_registry__load":
      return { model_id: modelId, path: paths.model, backend_id: backendId, hardware_profile: "cpu" };
    case "model_registry__unload":
      return { model_id: modelId, backend_id: backendId, hardware_profile: "cpu" };
    case "model_registry__install":
      return { model_id: modelId, source_uri: `file://${paths.model}`, backend_id: backendId };
    case "model_registry__apply":
      return { model_id: modelId, backend_id: backendId, hardware_profile: "cpu" };
    case "model_registry__delete":
      return { model_id: modelId, job_id: "toolcat-delete" };
    case "backend__health":
      return { backend_id: backendId, hardware_profile: "cpu" };
    case "backend__install":
      return { backend_id: backendId, source_uri: "gallery://toolcat/backend" };
    case "backend__apply":
      return { backend_id: backendId, hardware_profile: "cpu" };
    case "backend__start":
      return { backend_id: backendId, hardware_profile: "cpu" };
    case "backend__stop":
      return { backend_id: backendId, hardware_profile: "cpu" };
    case "backend__delete":
      return { backend_id: backendId };
    case "gallery__sync":
      return { gallery_id: "toolcat-gallery", source_uri: "gallery://toolcat/catalog" };
    case "memory__append":
      return { section: "workflow.notes", content: "TOOLCAT memory append canary." };
    case "memory__search":
      return { query: "TOOLCAT memory append canary" };
    case "memory__read":
      return { frame_id: memoryFrameIdFromText(historyText) };
    case "memory__replace":
      return { section: "workflow.notes", content: "TOOLCAT memory replace canary." };
    case "memory__clear":
      return { section: "workflow.notes" };
    case "monitor__create":
      return {
        title: "Toolcat disposable monitor",
        description: "Disposable live IDE monitor probe.",
        keywords: ["TOOLCAT_MONITOR_CANARY"],
        interval_seconds: 3600,
        source_prompt: "TOOLCAT_SINGLE_TOOL",
      };
    case "commerce__checkout":
      return {
        merchant_url: "https://example.invalid/toolcat-checkout",
        items: [{ id: "toolcat-fixture", quantity: 1 }],
        total_amount: 0.01,
        currency: "USD",
        buyer_email: "toolcat@example.invalid",
      };
    case "connector__toolcat__noop":
      return { fixture: "TOOLCAT_CONNECTOR_CANARY" };
    case "computer_use.request_lease":
      return {
        lane: "native_browser",
        session_mode: "controlled_relaunch",
        reason: `TOOLCAT provider-specific computer-use probe via ${providersUrl || "local runtime state"}.`,
      };
    default:
      return { fixture: "TOOLCAT_UNKNOWN_SINGLE_TOOL" };
  }
}

function singleToolProbe({ surface, rawCurrentTurn = "", currentSurface = "", called, failed, jsonTool }) {
  if (!/TOOLCAT_SINGLE_TOOL/i.test(surface)) return null;
  const toolName =
    extractMarker(currentSurface, "toolcat_tool") ||
    extractFirstMarker(currentSurface, "toolcat_tool") ||
    extractFirstMarker(rawCurrentTurn, "toolcat_tool") ||
    extractMarker(rawCurrentTurn, "toolcat_tool") ||
    extractFirstMarker(surface, "toolcat_tool") ||
    extractMarker(surface, "toolcat_tool");
  if (!toolName) {
    return jsonTool("chat__reply", {
      message: "TOOLCAT_SINGLE_TOOL fixture did not receive toolcat_tool marker.",
    });
  }
  if (failed(toolName)) {
    return jsonTool("chat__reply", {
      message: `TOOLCAT_SINGLE_TOOL ${toolName} live IDE probe failed; concrete trace failure recorded.`,
    });
  }
  const message = `TOOLCAT_SINGLE_TOOL ${toolName} live IDE probe reached the post-tool final reply path.`;
  if (toolName === "chat__reply") {
    return jsonTool("chat__reply", { message });
  }
  if (toolName === "agent__complete") {
    return jsonTool("agent__complete", { result: message });
  }
  const setupSteps = [];
  const currentTurnText = `${surface}\n${rawCurrentTurn}`;
  if (toolName === "file__edit" || toolName === "file__multi_edit") {
    const paths = workspacePaths(surface);
    setupSteps.push({ name: "file__read", args: { path: paths.editTarget } });
  }
  if (toolName === "agent__await" && !childSessionIdFromText(currentTurnText)) {
    setupSteps.push({
      name: "agent__delegate",
      args: {
        goal: "Return one sentence confirming the Rust Agent delegate tool row is reachable.",
        budget: 1,
        role: "verifier",
        success_criteria: "Delegate call is accepted and returns a child session id for agent__await.",
      },
    });
  }
  if (toolName === "shell__status" || toolName === "shell__input" || toolName === "shell__terminate") {
    setupSteps.push({
      name: "shell__start",
      ready: () => done("shell__start", called, failed) && commandIdFromText(currentTurnText) !== "toolcat-missing-command-id",
      args: singleToolArgs("shell__start", surface, rawCurrentTurn),
    });
  }
  if (toolName === "clipboard__paste") {
    setupSteps.push({
      name: "clipboard__copy",
      args: singleToolArgs("clipboard__copy", surface, rawCurrentTurn),
    });
  }
  if (toolName === "memory__search" || toolName === "memory__read") {
    setupSteps.push({
      name: "memory__append",
      args: singleToolArgs("memory__append", surface, rawCurrentTurn),
    });
  }
  if (toolName === "memory__read") {
    setupSteps.push({
      name: "memory__search",
      ready: () => done("memory__search", called, failed) && memoryFrameIdFromText(currentTurnText) !== 1,
      args: singleToolArgs("memory__search", surface, rawCurrentTurn),
    });
  }
  setupSteps.push(...browserFixtureSetupSteps(toolName, surface));
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      ...setupSteps,
      { name: toolName, args: () => singleToolArgs(toolName, surface, rawCurrentTurn) },
      ...finalSteps(message),
    ],
  });
}

function stage1Lifecycle({ surface, called, failed, jsonTool }) {
  if (!/TOOLCAT_STAGE1_LIFECYCLE/i.test(surface)) return null;
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      {
        name: "agent__delegate",
        args: {
          goal: "Return one sentence confirming the Rust tool catalogue lifecycle delegate path is reachable.",
          budget: 1,
          role: "verifier",
          success_criteria: "Delegate tool call is accepted or fails closed with a trace.",
        },
      },
      {
        name: "agent__await",
        args: () => ({
          child_session_id_hex:
            childSessionIdFromText(surface) ||
            "0000000000000000000000000000000000000000000000000000000000000000",
        }),
      },
      ...finalSteps(
        "TOOLCAT_STAGE1 live lifecycle probe covered agent__delegate, agent__await, chat__reply, and agent__complete through the governed Agent harness.",
      ),
    ],
  });
}

function stage1PauseEscalate({ surface, called, failed, jsonTool }) {
  if (!/TOOLCAT_STAGE1_PAUSE_ESCALATE/i.test(surface)) return null;
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      {
        name: "chat__reply",
        args: {
          message:
            "TOOLCAT_STAGE1 escalation control was attempted under Agent mode; the run should retain a concrete trace or failure verdict for agent__escalate.",
        },
      },
      {
        name: "agent__escalate",
        args: {
          reason: "Catalogue verification intentionally probes escalation control without executing an unsafe action.",
          missing_capability: "tool_catalogue_live_matrix.operator_escalation_probe",
        },
      },
      {
        name: "agent__pause",
        args: {
          reason: "Catalogue verification intentionally probes pause control as the last action in this scenario.",
        },
      },
    ],
  });
}

function stage2ReadModel({ surface, rawCurrentTurn, called, failed, jsonTool }) {
  if (!/TOOLCAT_STAGE2_READ_MODEL/i.test(surface)) return null;
  const paths = workspacePaths(surface);
  const statusUrl = extractMarker(surface, "browser_fixture_status_url");
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      { name: "file__list", args: { path: paths.root } },
      { name: "file__info", args: { path: paths.readme } },
      { name: "file__read", args: { path: paths.readme } },
      { name: "file__view", args: { path: paths.notes, start_line: 1, line_count: 4 } },
      { name: "file__search", args: { path: paths.root, regex: "TOOLCAT_CANARY", file_pattern: "*.txt" } },
      { name: "math__eval", args: { expression: "(247 * 38) + 12" } },
      { name: "model__embeddings", args: { text: "TOOLCAT memory embedding fixture" } },
      {
        name: "model__rerank",
        args: {
          query: "tool catalogue memory fixture",
          candidates: ["browser matrix", "memory fixture", "model registry"],
          top_k: 2,
        },
      },
      { name: "http__fetch", args: { url: statusUrl, max_chars: 1000 } },
      ...finalSteps(
        `TOOLCAT_STAGE2 read/local/model probe completed with filesystem reads, math__eval, model helpers, and http__fetch. Trace length marker: ${String(rawCurrentTurn || "").length}.`,
      ),
    ],
  });
}

function stage3FilesystemMutation({ surface, called, failed, jsonTool }) {
  if (!/TOOLCAT_STAGE3_FILESYSTEM_MUTATION/i.test(surface)) return null;
  const paths = workspacePaths(surface);
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      { name: "file__create_dir", args: { path: paths.scratchDir, recursive: true } },
      { name: "file__write", args: { path: paths.writeTarget, content: "first\nsecond\nthird\n" } },
      { name: "file__read", args: { path: paths.writeTarget } },
      { name: "file__edit", args: { path: paths.writeTarget, search: "second", replace: "second edited" } },
      {
        name: "file__multi_edit",
        args: {
          path: paths.writeTarget,
          edits: [
            { search: "first", replace: "first edited" },
            { search: "third", replace: "third edited" },
          ],
        },
      },
      { name: "file__copy", args: { source_path: paths.writeTarget, destination_path: paths.copyTarget, overwrite: true } },
      { name: "file__move", args: { source_path: paths.copyTarget, destination_path: paths.moveTarget, overwrite: true } },
      { name: "file__zip", args: { source_path: paths.scratchDir, destination_zip_path: paths.zipTarget, overwrite: true } },
      { name: "file__delete", args: { path: paths.moveTarget, ignore_missing: false } },
      { name: "file__delete", args: { path: "/tmp/ioi-toolcat-outside-delete-denied", ignore_missing: true } },
      ...finalSteps(
        "TOOLCAT_STAGE3 filesystem mutation probe exercised write, edit, multi_edit, copy, move, zip, delete, and an outside-scope delete gate.",
      ),
    ],
  });
}

function stage4ShellSoftware({ surface, rawCurrentTurn, called, failed, jsonTool }) {
  if (!/TOOLCAT_STAGE4_SHELL_SOFTWARE/i.test(surface)) return null;
  const paths = workspacePaths(surface);
  const commandId = () => commandIdFromText(rawCurrentTurn);
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      { name: "shell__cd", args: { path: paths.root } },
      { name: "shell__run", args: { command: "node", args: ["-e", "console.log('toolcat shell run ok')"] } },
      {
        name: "shell__start",
        args: {
          command: "node",
          args: ["-e", "process.stdin.resume(); process.stdin.on('data', d => { console.log('stdin:' + d.toString().trim()); });"],
          wait_ms_before_async: 100,
        },
      },
      { name: "shell__status", args: () => ({ command_id: commandId() }) },
      { name: "shell__input", args: () => ({ command_id: commandId(), stdin: "toolcat input\n" }) },
      { name: "shell__terminate", args: () => ({ command_id: commandId() }) },
      { name: "shell__reset", args: {} },
      {
        name: "software_install__resolve",
        args: {
        request: {
          target_text: "nonexistent-toolcat-fixture",
          target_kind: "command_line_tool",
          manager_preference: "apt-get",
          provenance: "live-ide-tool-catalogue-disposable-fixture",
        },
      },
      },
      { name: "software_install__execute_plan", args: { plan_ref: "toolcat-disposable-plan-ref" } },
      ...finalSteps(
        "TOOLCAT_STAGE4 shell/software probe covered shell run, retained command controls, shell reset, and install resolve/execute gates.",
      ),
    ],
  });
}

function stage4RetainedShellControls({ surface, rawCurrentTurn, called, failed, jsonTool }) {
  if (!/TOOLCAT_STAGE4_RETAINED_SHELL_CONTROLS/i.test(surface)) return null;
  const paths = workspacePaths(surface);
  const commandId = () => commandIdFromText(rawCurrentTurn);
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      { name: "shell__cd", args: { path: paths.root } },
      {
        name: "shell__start",
        args: {
          command: "node",
          args: ["-e", "process.stdin.resume(); process.stdin.on('data', d => { console.log('stdin:' + d.toString().trim()); });"],
          wait_ms_before_async: 100,
        },
      },
      { name: "shell__status", args: () => ({ command_id: commandId() }) },
      { name: "shell__input", args: () => ({ command_id: commandId(), stdin: "toolcat input\n" }) },
      { name: "shell__terminate", args: () => ({ command_id: commandId() }) },
      { name: "shell__reset", args: {} },
      ...finalSteps("Retained shell controls completed against a disposable command; details are available in Tracing."),
    ],
  });
}

function stage5Browser({ surface, rawCurrentTurn, called, failed, jsonTool }) {
  if (!/TOOLCAT_STAGE5_BROWSER/i.test(surface)) return null;
  const url = extractMarker(surface, "browser_fixture_url");
  const uploadPath = extractMarker(surface, "workspace_fixture_upload");
  const tabId = () => tabIdFromText(rawCurrentTurn);
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      { name: "browser__navigate", args: { url } },
      { name: "browser__inspect", args: {} },
      { name: "browser__find_text", args: { query: "TOOLCAT_BROWSER_CANARY", scope: "document", scroll: true } },
      { name: "browser__screenshot", args: { full_page: false } },
      { name: "browser__list_options", args: { selector: "#toolcat-select" } },
      { name: "browser__select_option", args: { selector: "#toolcat-select", value: "beta" } },
      { name: "browser__click", args: { selector: "#toolcat-input" } },
      { name: "browser__type", args: { selector: "#toolcat-input", text: "typed through browser__type" } },
      { name: "browser__press_key", args: { selector: "#toolcat-input", key: "a", modifiers: ["Control"] } },
      { name: "browser__select", args: { selector: "#fixture-copy", start_offset: 0, end_offset: 23 } },
      { name: "browser__copy", args: {} },
      { name: "browser__paste", args: { selector: "#toolcat-input" } },
      { name: "browser__wait", args: { condition: "text_present", query: "TOOLCAT_BROWSER_CANARY", scope: "document", timeout_ms: 3000 } },
      { name: "browser__upload", args: { paths: [uploadPath], selector: "#toolcat-file" } },
      { name: "browser__click", args: { selector: "#second-link" } },
      { name: "browser__back", args: { steps: 1 } },
      { name: "browser__list_tabs", args: {} },
      { name: "browser__switch_tab", args: () => ({ tab_id: tabId() }) },
      { name: "browser__close_tab", args: { tab_id: "toolcat-nonexistent-tab" } },
      { name: "browser__inspect_canvas", args: { selector: "#toolcat-canvas" } },
      { name: "browser__hover", args: { selector: "#toolcat-button", duration_ms: 100 } },
      {
        name: "browser__move_pointer",
        args: { observation_ref: "toolcat-observation", coordinate_space_id: "viewport_css_px", semantic_id: "toolcat-canvas", x: 48, y: 48 },
      },
      { name: "browser__pointer_down", args: { button: "left" } },
      { name: "browser__pointer_up", args: { button: "left" } },
      { name: "browser__click_at", args: { id: "grp_blue_square_canvas" } },
      { name: "browser__scroll", args: { delta_y: 180, delta_x: 0 } },
      {
        name: "browser__subagent",
        args: {
          task_name: "tool catalogue browser fixture",
          task_summary: "Verify browser subagent packaging reaches the fixture page.",
          recording_name: "toolcat-browser-subagent",
          task: `Use browser__navigate to open ${url}, then inspect the browser page and report the TOOLCAT_BROWSER_CANARY text without taking external actions.`,
        },
      },
      ...finalSteps(
        "TOOLCAT_STAGE5 browser matrix attempted navigation, inspection, DOM controls, upload/tab/pointer/canvas/subagent paths, with pass or concrete per-tool verdicts in trace.",
      ),
    ],
  });
}

function stage6DesktopClipboard({ surface, called, failed, jsonTool }) {
  if (!/TOOLCAT_STAGE6_DESKTOP_CLIPBOARD/i.test(surface)) return null;
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      { name: "screen__inspect", args: {} },
      { name: "screen__find", args: { query: "Connect Wallet" } },
      { name: "window__focus", args: { title: "Autopilot" } },
      { name: "clipboard__copy", args: { content: "TOOLCAT_CLIPBOARD_CANARY" } },
      { name: "clipboard__paste", args: {} },
      { name: "screen__type", args: { text: "toolcat desktop type probe" } },
      { name: "screen__scroll", args: { delta_y: 120, delta_x: 0 } },
      { name: "screen__click", args: { id: "toolcat-nonexistent-control" } },
      { name: "screen__click_at", args: { x: 10, y: 10 } },
      { name: "screen", args: { action: "screenshot" } },
      { name: "app__launch", args: { app_name: "autopilot-nonexistent-toolcat-fixture" } },
      ...finalSteps(
        "TOOLCAT_STAGE6 desktop/clipboard probe covered screen, window focus, app launch gate, and clipboard primitives without mixing Ask and Agent responsibilities.",
      ),
    ],
  });
}

function stage7ModelRegistry({ surface, called, failed, jsonTool }) {
  if (!/TOOLCAT_STAGE7_MODEL_REGISTRY/i.test(surface)) return null;
  const paths = workspacePaths(surface);
  const modelId = "toolcat/live-fixture-model";
  const backendId = "backend.toolcat.fixture";
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      { name: "backend__health", args: { backend_id: backendId, hardware_profile: "cpu" } },
      { name: "model_registry__load", args: { model_id: modelId, path: paths.model, backend_id: backendId, hardware_profile: "cpu" } },
      { name: "model_registry__unload", args: { model_id: modelId, backend_id: backendId, hardware_profile: "cpu" } },
      { name: "model_registry__install", args: { model_id: modelId, source_uri: `file://${paths.model}`, backend_id: backendId } },
      { name: "model_registry__apply", args: { model_id: modelId, backend_id: backendId, hardware_profile: "cpu" } },
      { name: "model_registry__delete", args: { model_id: modelId, job_id: "toolcat-delete" } },
      { name: "backend__install", args: { backend_id: backendId, source_uri: "gallery://toolcat/backend" } },
      { name: "backend__apply", args: { backend_id: backendId, hardware_profile: "cpu" } },
      { name: "backend__start", args: { backend_id: backendId, hardware_profile: "cpu" } },
      { name: "backend__stop", args: { backend_id: backendId, hardware_profile: "cpu" } },
      { name: "backend__delete", args: { backend_id: backendId } },
      { name: "gallery__sync", args: { gallery_id: "toolcat-gallery", source_uri: "gallery://toolcat/catalog" } },
      ...finalSteps(
        "TOOLCAT_STAGE7 model registry/backend/gallery probe attempted every lifecycle control with fixture IDs for pass, gate, blocker, or failure classification.",
      ),
    ],
  });
}

function stage8MemoryCommerceMonitor({ surface, called, failed, jsonTool }) {
  if (!/TOOLCAT_STAGE8_MEMORY_COMMERCE_MONITOR/i.test(surface)) return null;
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      { name: "memory__append", args: { section: "workflow.notes", content: "TOOLCAT memory append canary." } },
      { name: "memory__search", args: { query: "TOOLCAT memory append canary" } },
      { name: "memory__read", args: { frame_id: 1 } },
      { name: "memory__replace", args: { section: "workflow.notes", content: "TOOLCAT memory replace canary." } },
      { name: "memory__clear", args: { section: "workflow.notes" } },
      {
        name: "monitor__create",
        args: {
          title: "Toolcat disposable monitor",
          description: "Disposable live IDE monitor probe.",
          keywords: ["TOOLCAT_MONITOR_CANARY"],
          interval_seconds: 3600,
          source_prompt: "TOOLCAT_STAGE8_MEMORY_COMMERCE_MONITOR",
        },
      },
      {
        name: "commerce__checkout",
        args: {
          merchant_url: "https://example.invalid/toolcat-checkout",
          items: [{ id: "toolcat-fixture", quantity: 1 }],
          total_amount: 0.01,
          currency: "USD",
          buyer_email: "toolcat@example.invalid",
        },
      },
      { name: "connector__toolcat__noop", args: { fixture: "TOOLCAT_CONNECTOR_CANARY" } },
      ...finalSteps(
        "TOOLCAT_STAGE8 memory, monitor, commerce, and dynamic connector probes were attempted through Agent mode with disposable fixture data.",
      ),
    ],
  });
}

function stage9Media({ surface, called, failed, jsonTool }) {
  if (!/TOOLCAT_STAGE9_MEDIA/i.test(surface)) return null;
  const mediaUrl = extractMarker(surface, "browser_fixture_media_url");
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      { name: "media__vision_read", args: { image_base64: PIXEL_PNG_BASE64, mime_type: "image/png", prompt: "Describe this toolcat pixel fixture." } },
      { name: "media__transcribe_audio", args: { audio_base64: "", mime_type: "audio/wav", language: "en" } },
      { name: "media__generate_image", args: { prompt: "A tiny tool catalogue verification badge", mime_type: "image/png" } },
      { name: "media__edit_image", args: { source_image_base64: PIXEL_PNG_BASE64, source_mime_type: "image/png", prompt: "Add a small verification dot." } },
      { name: "media__generate_video", args: { prompt: "One second verification card", mime_type: "video/mp4", duration_ms: 1000 } },
      { name: "media__synthesize_speech", args: { text: "Tool catalogue verification", mime_type: "audio/wav" } },
      { name: "media__extract_transcript", args: { url: mediaUrl, language: "en", max_chars: 1000 } },
      { name: "media__extract_evidence", args: { url: mediaUrl, language: "en", max_chars: 1000, frame_limit: 1 } },
      ...finalSteps(
        "TOOLCAT_STAGE9 media probe attempted vision, transcription, generation, editing, video, speech, transcript, and evidence extraction paths.",
      ),
    ],
  });
}

function stage10ComputerUseProviders({ surface, called, failed, jsonTool }) {
  if (!/TOOLCAT_STAGE10_COMPUTER_USE_PROVIDER/i.test(surface)) return null;
  const providersUrl = extractMarker(surface, "computer_use_providers_url");
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      { name: "http__fetch", args: { url: providersUrl, max_chars: 4000 } },
      {
        name: "computer_use.request_lease",
        args: {
          lane: "native_browser",
          session_mode: "controlled_relaunch",
          reason: "TOOLCAT provider-specific computer-use live IDE matrix probe.",
        },
      },
      {
        name: "agent__escalate",
        args: {
          reason: "Provider-specific computer-use lease is not exposed as a first-class Rust Agent Studio tool in this surface.",
          missing_capability: "computer_use.request_lease",
        },
      },
      ...finalSteps(
        "TOOLCAT_STAGE10 provider computer-use probe fetched provider state and attempted/requested the lease path for external-blocker or missing-tool classification.",
      ),
    ],
  });
}

function stage11WorkflowCrossSurface({ surface, called, failed, jsonTool }) {
  if (!/TOOLCAT_STAGE11_WORKFLOW_CROSS_SURFACE/i.test(surface)) return null;
  const paths = workspacePaths(surface);
  const statusUrl = extractMarker(surface, "browser_fixture_status_url");
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      { name: "file__read", args: { path: paths.readme } },
      { name: "http__fetch", args: { url: statusUrl, max_chars: 1000 } },
      { name: "browser__navigate", args: { url: extractMarker(surface, "browser_fixture_url") } },
      { name: "browser__inspect", args: {} },
      { name: "clipboard__copy", args: { content: "TOOLCAT_STAGE11_CROSS_SURFACE" } },
      ...finalSteps(
        "TOOLCAT_STAGE11 cross-surface workflow used file, HTTP, browser inspect, clipboard, chat reply, and completion in one governed Agent turn.",
      ),
    ],
  });
}

function stage12FinalRegression({ surface, called, failed, jsonTool }) {
  if (!/TOOLCAT_STAGE12_FINAL_REGRESSION/i.test(surface)) return null;
  return runChain({
    called,
    failed,
    jsonTool,
    steps: [
      ...finalSteps(
        "TOOLCAT_STAGE12 final regression confirms a simple governed conversational Agent turn returns through chat__reply quickly without documented-work leakage.",
      ),
    ],
  });
}

const STAGE_HANDLERS = [
  singleToolProbe,
  stage1Lifecycle,
  stage1PauseEscalate,
  stage2ReadModel,
  stage3FilesystemMutation,
  stage4RetainedShellControls,
  stage4ShellSoftware,
  stage5Browser,
  stage6DesktopClipboard,
  stage7ModelRegistry,
  stage8MemoryCommerceMonitor,
  stage9Media,
  stage10ComputerUseProviders,
  stage11WorkflowCrossSurface,
  stage12FinalRegression,
];

export function nativeFixtureToolCatalogueResponse({
  surface = "",
  rawCurrentTurn = "",
  currentSurface = "",
  called,
  failed,
  jsonTool,
} = {}) {
  const text = `${surface}\n${rawCurrentTurn}`;
  if (!/\bTOOLCAT_STAGE\d+_/i.test(text)) return null;
  const callState = typeof called === "function" ? called : () => false;
  const failState = typeof failed === "function" ? failed : () => false;
  for (const handler of STAGE_HANDLERS) {
    const response = handler({
      surface: text,
      rawCurrentTurn,
      currentSurface,
      called: callState,
      failed: failState,
      jsonTool,
    });
    if (response) return response;
  }
  return jsonTool("chat__reply", {
    message: "TOOLCAT catalogue fixture did not match a concrete stage; classify this as a fixture routing failure.",
  });
}
