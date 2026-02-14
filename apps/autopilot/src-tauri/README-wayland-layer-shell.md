# Wayland Right-Dock Migration Notes

## Date
- February 13, 2026

## Decision Gate: GTK3 vs GTK4
- Result: **GTK3 selected** for this migration.
- Reason 1: The current app already uses `gtk = 0.18` in `src-tauri` and Linux window hooks are GTK3-based (`window.gtk_window()` paths).
- Reason 2: A GTK4 migration would require broader Tauri/WRY integration validation before this docking fix and would expand scope beyond right-dock reliability.
- Rule outcome: Because a GTK4-native handle path was not readily available in current lifecycle code without larger rework, this migration proceeds with GTK3 layer-shell bindings.

## Runtime/Build Requirements
- Runtime package (Debian/Ubuntu): `libgtk-layer-shell0`
- Dev package (local build): `libgtk-layer-shell-dev`

This machine currently reports missing pkg-config metadata for layer-shell:
- `pkg-config gtk-layer-shell-0` -> not found

## Environment Controls
- `AUTOPILOT_WAYLAND_LAYER_SHELL=0`
  - Disables Wayland layer-shell backend and forces legacy positioning behavior.
- `AUTOPILOT_WAYLAND_FORCE_LEGACY=1`
  - Hard forces legacy backend even on Wayland when layer-shell is otherwise available.
- `AUTOPILOT_FORCE_X11=1`
  - Existing control that forces X11 backend at startup.

## Behavior Changes
- On Linux Wayland with layer-shell backend active:
  - Right-dock is anchored via layer-shell.
  - `center`/`float` mode requests are coerced to `right`.
  - Overlay mode uses `exclusive_zone=0` (no work-area reservation).
- If layer-shell init/configuration fails at runtime:
  - Session falls back to legacy backend and logs a warning.
