import assert from "node:assert/strict";
import test from "node:test";

import { nativeFixtureToolCatalogueResponse } from "./native-fixture-tool-catalogue.mjs";

test("single-tool catalogue fixture uses the current query marker before history", () => {
  const surface = [
    "TOOLCAT_STAGE1_LIFECYCLE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=agent__await",
    "TOOLCAT_STAGE1_LIFECYCLE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=agent__delegate",
  ].join("\n");

  const response = nativeFixtureToolCatalogueResponse({
    surface,
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "agent__delegate");
});

test("single-tool catalogue fixture prefers current turn marker over stale surface markers", () => {
  const response = nativeFixtureToolCatalogueResponse({
    surface: [
      "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__start",
      "Tool Output (shell__start): {\"command_id\":\"shell__start:1111111111111111111111111111111111111111111111111111111111111111\"}",
    ].join("\n"),
    rawCurrentTurn:
      "user: TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__reset",
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "shell__reset");
  assert.deepEqual(response.arguments, {});
});

test("single-tool catalogue fixture uses latest current surface marker before stale raw markers", () => {
  const response = nativeFixtureToolCatalogueResponse({
    surface: [
      "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__reset",
      "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=chat__reply",
    ].join("\n"),
    currentSurface: [
      "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__reset",
      "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=chat__reply",
    ].join("\n"),
    rawCurrentTurn:
      "user: TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__reset",
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "chat__reply");
  assert.equal(
    response.arguments.message,
    "TOOLCAT_SINGLE_TOOL chat__reply live IDE probe reached the post-tool final reply path.",
  );
});

test("single-tool delegate catalogue fixture uses the Rust numeric budget contract", () => {
  const response = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE1_LIFECYCLE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=agent__delegate",
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "agent__delegate");
  assert.equal(response.arguments.budget, 1);
});

test("single-tool await catalogue fixture reuses a prior delegated child id when present", () => {
  const childId = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
  const response = nativeFixtureToolCatalogueResponse({
    surface: [
      "TOOLCAT_STAGE1_LIFECYCLE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=agent__await",
      `Tool Output (agent__delegate): {"child_session_id_hex":"${childId}"}`,
    ].join("\n"),
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "agent__await");
  assert.equal(response.arguments.child_session_id_hex, childId);
});

test("single-tool await catalogue fixture delegates before await when no child id exists", () => {
  const response = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE1_LIFECYCLE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=agent__await",
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "agent__delegate");
});

test("single-tool catalogue fixture reports failed exact rows instead of advancing to success", () => {
  const response = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE1_LIFECYCLE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=agent__await",
    called: () => false,
    failed: (name) => name === "agent__await",
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "chat__reply");
  assert.match(response.arguments.message, /agent__await live IDE probe failed/);
});

test("single-tool edit rows read the target before mutating it", () => {
  const surface = [
    "TOOLCAT_STAGE3_FILESYSTEM_MUTATION_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=file__edit",
    "workspace_fixture_root=/tmp/toolcat-root",
    "workspace_fixture_edit_target=/tmp/toolcat-root/edit-target.txt",
  ].join(" ");

  const first = nativeFixtureToolCatalogueResponse({
    surface,
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(first.name, "file__read");
  assert.deepEqual(first.arguments, { path: "/tmp/toolcat-root/edit-target.txt" });

  const second = nativeFixtureToolCatalogueResponse({
    surface,
    called: (name) => name === "file__read",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(second.name, "file__edit");
  assert.equal(second.arguments.path, "/tmp/toolcat-root/edit-target.txt");
});

test("single-tool zip fixture writes the archive outside the zipped directory", () => {
  const response = nativeFixtureToolCatalogueResponse({
    surface: [
      "TOOLCAT_STAGE3_FILESYSTEM_MUTATION_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=file__zip",
      "workspace_fixture_root=/tmp/toolcat-root",
    ].join(" "),
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "file__zip");
  assert.equal(response.arguments.source_path, "/tmp/toolcat-root/scratch");
  assert.equal(response.arguments.destination_zip_path, "/tmp/toolcat-root/archive.zip");
});

test("single-tool retained shell rows launch a command before inspecting it", () => {
  const surface = "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__status";
  const commandId = "shell__start:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

  const first = nativeFixtureToolCatalogueResponse({
    surface,
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(first.name, "shell__start");

  const second = nativeFixtureToolCatalogueResponse({
    surface,
    rawCurrentTurn: `Tool Output (shell__start): {"command_id":"${commandId}"}`,
    called: (name) => name === "shell__start",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(second.name, "shell__status");
  assert.equal(second.arguments.command_id, commandId);
});

test("single-tool retained shell rows ignore previous-turn command ids until this run starts one", () => {
  const commandId = "shell__start:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
  const response = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__terminate",
    rawCurrentTurn: `Earlier trace outside this run had {"command_id":"${commandId}"}`,
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "shell__start");
});

test("single-tool retained shell rows parse escaped command ids without swallowing context", () => {
  const commandId = "shell__start:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
  const response = nativeFixtureToolCatalogueResponse({
    surface: [
      "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__input",
      `Tool Output (shell__start): {\\"command_id\\":\\"${commandId}\\"}`,
      "=== LAYER 3: WORKSPACE CONTEXT (Untrusted Reference) ===",
    ].join("\n"),
    called: (name) => name === "shell__start",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "shell__input");
  assert.equal(response.arguments.command_id, commandId);
});

test("single-tool retained shell rows do not treat global shell start as current command id", () => {
  const response = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__terminate",
    rawCurrentTurn: "No retained command id is present in this isolated turn.",
    called: (name) => name === "shell__start",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "shell__start");
});

test("focused retained shell lifecycle chains through input and terminate", () => {
  const surface = "TOOLCAT_STAGE4_RETAINED_SHELL_CONTROLS workspace_fixture_root=/tmp/toolcat-root";
  const commandId = "shell__start:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
  const jsonTool = (name, args) => ({ name, arguments: args });

  assert.equal(
    nativeFixtureToolCatalogueResponse({
      surface,
      called: () => false,
      failed: () => false,
      jsonTool,
    }).name,
    "shell__cd",
  );

  assert.equal(
    nativeFixtureToolCatalogueResponse({
      surface,
      called: (name) => name === "shell__cd",
      failed: () => false,
      jsonTool,
    }).name,
    "shell__start",
  );

  const status = nativeFixtureToolCatalogueResponse({
    surface,
    rawCurrentTurn: `Tool Output (shell__start): {"command_id":"${commandId}"}`,
    called: (name) => ["shell__cd", "shell__start"].includes(name),
    failed: () => false,
    jsonTool,
  });
  assert.equal(status.name, "shell__status");
  assert.equal(status.arguments.command_id, commandId);

  const input = nativeFixtureToolCatalogueResponse({
    surface,
    rawCurrentTurn: `Tool Output (shell__start): {"command_id":"${commandId}"}`,
    called: (name) => ["shell__cd", "shell__start", "shell__status"].includes(name),
    failed: () => false,
    jsonTool,
  });
  assert.equal(input.name, "shell__input");
  assert.equal(input.arguments.command_id, commandId);

  const terminate = nativeFixtureToolCatalogueResponse({
    surface,
    rawCurrentTurn: `Tool Output (shell__start): {"command_id":"${commandId}"}`,
    called: (name) => ["shell__cd", "shell__start", "shell__status", "shell__input"].includes(name),
    failed: () => false,
    jsonTool,
  });
  assert.equal(terminate.name, "shell__terminate");
  assert.equal(terminate.arguments.command_id, commandId);
});

test("software install resolver fixture uses a supported executable manager", () => {
  const response = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=software_install__resolve",
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "software_install__resolve");
  assert.equal(response.arguments.request.manager_preference, "apt-get");
});

test("single-tool clipboard paste rows seed disposable clipboard content", () => {
  const surface = "TOOLCAT_STAGE6_DESKTOP_CLIPBOARD_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=clipboard__paste";

  const first = nativeFixtureToolCatalogueResponse({
    surface,
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(first.name, "clipboard__copy");
  assert.equal(first.arguments.content, "TOOLCAT_CLIPBOARD_CANARY");

  const second = nativeFixtureToolCatalogueResponse({
    surface,
    called: (name) => name === "clipboard__copy",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(second.name, "clipboard__paste");
  assert.deepEqual(second.arguments, {});
});

test("screen find fixture targets the deterministic accessibility tree", () => {
  const response = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE6_DESKTOP_CLIPBOARD_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=screen__find",
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "screen__find");
  assert.equal(response.arguments.query, "Connect Wallet");
});

test("screen click fixtures target the deterministic accessibility tree", () => {
  const click = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE6_DESKTOP_CLIPBOARD_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=screen__click",
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(click.name, "screen__click");
  assert.equal(click.arguments.id, "btn-1");

  const clickAt = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE6_DESKTOP_CLIPBOARD_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=screen__click_at",
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(clickAt.name, "screen__click_at");
  assert.deepEqual(clickAt.arguments, { x: 200, y: 125 });
});

test("browser DOM single-tool rows bootstrap the fixture page before acting", () => {
  const surface = "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__click browser_fixture_url=http://127.0.0.1:12345/";

  const first = nativeFixtureToolCatalogueResponse({
    surface,
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(first.name, "browser__navigate");
  assert.deepEqual(first.arguments, { url: "http://127.0.0.1:12345/" });

  const second = nativeFixtureToolCatalogueResponse({
    surface,
    called: (name) => name === "browser__navigate",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(second.name, "browser__click");
  assert.deepEqual(second.arguments, { selector: "#toolcat-input" });
});

test("browser paste row seeds the clipboard before pasting into the fixture", () => {
  const surface = "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__paste browser_fixture_url=http://127.0.0.1:12345/";

  const afterNavigate = nativeFixtureToolCatalogueResponse({
    surface,
    called: (name) => name === "browser__navigate",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(afterNavigate.name, "clipboard__copy");
  assert.deepEqual(afterNavigate.arguments, { content: "TOOLCAT_CLIPBOARD_CANARY" });

  const afterCopySetup = nativeFixtureToolCatalogueResponse({
    surface,
    called: (name) => name === "browser__navigate" || name === "clipboard__copy",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(afterCopySetup.name, "browser__paste");
  assert.deepEqual(afterCopySetup.arguments, { selector: "#toolcat-input" });
});

test("browser tab control rows list tabs before using a tab id", () => {
  const surface = [
    "TOOLCAT_STAGE5_BROWSER_SINGLE",
    "TOOLCAT_SINGLE_TOOL",
    "toolcat_tool=browser__switch_tab",
    "browser_fixture_url=http://127.0.0.1:12345/",
  ].join(" ");
  const rawCurrentTurn = 'Tool Output (browser__list_tabs): {"tabs":[{"tab_id":"tab-fixture","title":"Fixture"}]}';

  const setup = nativeFixtureToolCatalogueResponse({
    surface,
    called: (name) => name === "browser__navigate",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(setup.name, "browser__list_tabs");

  const target = nativeFixtureToolCatalogueResponse({
    surface,
    rawCurrentTurn,
    called: (name) => name === "browser__navigate" || name === "browser__list_tabs",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(target.name, "browser__switch_tab");
  assert.deepEqual(target.arguments, { tab_id: "tab-fixture" });
});

test("browser click-at fixture uses the grounded observation id", () => {
  const setup = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__click_at browser_fixture_url=http://127.0.0.1:12345/",
    called: (name) => name === "browser__navigate",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(setup.name, "browser__inspect");

  const response = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__click_at browser_fixture_url=http://127.0.0.1:12345/",
    called: (name) => name === "browser__navigate" || name === "browser__inspect",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "browser__click_at");
  assert.deepEqual(response.arguments, { id: "toolcat-canvas" });
});

test("browser subagent fixture task is explicitly browser-first and URL-grounded", () => {
  const response = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__subagent browser_fixture_url=http://127.0.0.1:12345/",
    called: (name) => name === "browser__navigate",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(response.name, "browser__subagent");
  assert.equal(response.arguments.task_name, "tool catalogue browser fixture");
  assert.match(response.arguments.task, /Use browser__navigate to open http:\/\/127\.0\.0\.1:12345\//);
  assert.match(response.arguments.task, /TOOLCAT_BROWSER_CANARY/);
});

test("memory core write fixtures use an allowed writable section", () => {
  const append = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE8_MEMORY_COMMERCE_MONITOR_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=memory__append",
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(append.name, "memory__append");
  assert.equal(append.arguments.section, "workflow.notes");

  const clear = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE8_MEMORY_COMMERCE_MONITOR_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=memory__clear",
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(clear.name, "memory__clear");
  assert.equal(clear.arguments.section, "workflow.notes");
});

test("memory read fixture consumes the latest memory search inspect id", () => {
  const read = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE8_MEMORY_COMMERCE_MONITOR_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=memory__read",
    rawCurrentTurn:
      "Tool Output (memory__search): - [ID:1000000000042] Scope:desktop.core_memory.audit Kind:core_memory_update",
    called: (name) => name === "memory__append" || name === "memory__search",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(read.name, "memory__read");
  assert.deepEqual(read.arguments, { frame_id: 1000000000042 });
});

test("memory search/read single-tool rows seed memory before retrieval", () => {
  const search = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE8_MEMORY_COMMERCE_MONITOR_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=memory__search",
    called: () => false,
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(search.name, "memory__append");

  const readSetup = nativeFixtureToolCatalogueResponse({
    surface: "TOOLCAT_STAGE8_MEMORY_COMMERCE_MONITOR_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=memory__read",
    called: (name) => name === "memory__append",
    failed: () => false,
    jsonTool: (name, args) => ({ name, arguments: args }),
  });

  assert.equal(readSetup.name, "memory__search");
});
