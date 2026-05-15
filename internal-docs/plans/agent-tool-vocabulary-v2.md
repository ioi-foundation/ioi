# Agent Tool Vocabulary V2

This document is the source of truth for the native agent tool vocabulary cutover.

## Goals

- Preserve the `namespace__action` protocol shape for native and MCP tool separation.
- Replace awkward nouns and implementation-heavy verbs with a cleaner, more orthogonal vocabulary.
- Remove the overlapping `filesystem__` / `sys__` / `gui__` / `ui__` / `os__` / `system__fail` native surface.

## Rename Map

### File tools

- `filesystem__write_file` -> `file__write`
- `filesystem__edit_file` -> `file__edit`
- `filesystem__read_file` -> `file__read`
- `filesystem__list_dir` -> `file__list`
- `filesystem__search_files` -> `file__search`
- `filesystem__stat_path` -> `file__info`
- `filesystem__move_path` -> `file__move`
- `filesystem__copy_path` -> `file__copy`
- `filesystem__delete_path` -> `file__delete`
- `filesystem__create_dir` -> `file__create_dir`
- `filesystem__zip` -> `file__zip`

### Shell and package tools

- `sys__exec` -> `shell__run`
- `sys__exec_session` -> `shell__start`
- `sys__exec_session_reset` -> `shell__reset`
- `sys__change_directory` -> `shell__cd`
- `sys__install_package` -> `package__install`

### Browser tools

- `browser__snapshot` -> `browser__inspect`
- `browser__click_element` -> `browser__click`
- `browser__move_mouse` -> `browser__move_pointer`
- `browser__mouse_down` -> `browser__pointer_down`
- `browser__mouse_up` -> `browser__pointer_up`
- `browser__synthetic_click` -> `browser__click_at`
- `browser__select_text` -> `browser__select`
- `browser__key` -> `browser__press_key`
- `browser__copy_selection` -> `browser__copy`
- `browser__paste_clipboard` -> `browser__paste`
- `browser__canvas_summary` -> `browser__inspect_canvas`
- `browser__upload_file` -> `browser__upload`
- `browser__dropdown_options` -> `browser__list_options`
- `browser__select_dropdown` -> `browser__select_option`
- `browser__go_back` -> `browser__back`
- `browser__tab_list` -> `browser__list_tabs`
- `browser__tab_switch` -> `browser__switch_tab`
- `browser__tab_close` -> `browser__close_tab`

`browser__click` becomes the single semantic click primitive. It may target by CSS `selector`, semantic `id`, ordered `ids`, or `continue_with`.

### Screen, window, clipboard, and app tools

- `computer` -> `screen`
- `gui__click` -> `screen__click_at`
- `gui__type` -> `screen__type`
- `gui__scroll` -> `screen__scroll`
- `gui__snapshot` -> `screen__inspect`
- `gui__click_element` -> `screen__click`
- `ui__find` -> `screen__find`
- `os__focus_window` -> `window__focus`
- `os__copy` -> `clipboard__copy`
- `os__paste` -> `clipboard__paste`
- `os__launch_app` -> `app__launch`

### Other tools

- `net__fetch` -> `http__fetch`
- `media__extract_multimodal_evidence` -> `media__extract_evidence`
- `automation__create_monitor` -> `monitor__create`
- `memory__inspect` -> `memory__read`
- `memory__replace_core` -> `memory__replace`
- `memory__append_core` -> `memory__append`
- `memory__clear_core` -> `memory__clear`
- `agent__await_result` -> `agent__await`
- `system__fail` -> `agent__escalate`

## Migration Rules

- Native tool definitions, policy targets, middleware normalization, prompt guidance, MCP collision rules, and test harnesses must use only the V2 names.
- Legacy names may survive only as transient model-ingress adapters at the normalization boundary while the branch is in flight.
- Historical evidence fixtures are allowed to preserve old names only if they are immutable archival artifacts and not part of the active runtime or test oracle surface.
