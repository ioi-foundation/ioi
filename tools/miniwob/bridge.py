#!/usr/bin/env python3
"""MiniWoB bridge for the computer_use_suite.

This bridge keeps the Rust harness on the exact page under test:
- it materializes instrumented MiniWoB task pages under a session temp dir
- the Rust harness navigates Chromium to the returned file:// URL
- page-side JS reports reward/termination/visible state back to this API
- oracle commands are queued here and executed inside the page as MiniWoB-local shortcuts
"""

from __future__ import annotations

import argparse
import atexit
import importlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse


SESSION_ROOT = Path(tempfile.gettempdir()) / "ioi-miniwob-bridge"
SOURCE_ENV_KEYS = [
    "COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR",
    "MINIWOB_SOURCE_DIR",
]
SYNC_HISTORY_LIMIT = 512
SYNC_HISTORY_TEXT_LIMIT = 240


def _discover_html_root() -> Path:
    for key in SOURCE_ENV_KEYS:
        raw = os.environ.get(key, "").strip()
        if not raw:
            continue
        candidate = Path(raw).expanduser().resolve()
        probe_paths = [
            candidate,
            candidate / "html",
            candidate / "miniwob" / "html",
        ]
        for probe in probe_paths:
            if (probe / "core" / "core.js").is_file() and (probe / "miniwob").is_dir():
                return probe
        raise RuntimeError(
            f"{key}={candidate} does not point to a MiniWoB html root or repo checkout"
        )

    try:
        miniwob = importlib.import_module("miniwob")
    except Exception as exc:  # pragma: no cover - exercised in runtime environment
        raise RuntimeError(
            "MiniWoB assets not found. Set COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR to a "
            "miniwob-plusplus checkout, or install the Python miniwob package."
        ) from exc

    html_root = Path(miniwob.__file__).resolve().parent / "html"
    if not (html_root / "core" / "core.js").is_file():
        raise RuntimeError(f"Discovered MiniWoB package at {html_root} without html assets")
    return html_root


def _normalize_env_id(env_id: str) -> str:
    normalized = env_id.strip()
    if normalized.startswith("miniwob/"):
        normalized = normalized.split("/", 1)[1]
    if normalized.endswith("-v1"):
        normalized = normalized[:-3]
    return normalized


def _json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _js_instrumentation(config: Dict[str, Any]) -> str:
    config_json = json.dumps(config, separators=(",", ":"))
    return f"""
<script>
(function() {{
  const bridge = {config_json};
  if (window.__IOI_MINIWOB_BRIDGE_BOOTSTRAPPED__ === bridge.generation) {{
    return;
  }}
  window.__IOI_MINIWOB_BRIDGE_BOOTSTRAPPED__ = bridge.generation;
  window.__IOI_MINIWOB_STICKY_TERMINAL__ = null;

  let actionCounter = 0;
  let lastOracleSeq = 0;
  let syncTimer = null;
  let heartbeatTimer = null;
  let lastEventSummary = null;
  let lastMoveSyncMs = 0;
  let lastPointerPosition = null;
  let pointerMotionArmed = false;
  let startupPointerNoiseGuardUntilMs = 0;

  function normalizeText(value) {{
    return String(value || "").replace(/\\s+/g, " ").trim();
  }}

  function isVisible(node) {{
    if (!node || typeof node.getBoundingClientRect !== "function") {{
      return false;
    }}
    const rect = node.getBoundingClientRect();
    if (!(rect.width > 0 && rect.height > 0)) {{
      return false;
    }}
    const style = window.getComputedStyle(node);
    return style.display !== "none" && style.visibility !== "hidden";
  }}

  function cssEscape(value) {{
    if (window.CSS && typeof window.CSS.escape === "function") {{
      return window.CSS.escape(String(value));
    }}
    return String(value).replace(/[^a-zA-Z0-9_-]/g, "\\$&");
  }}

  function selectorFor(node) {{
    if (!node || !node.tagName) {{
      return null;
    }}
    if (node.id) {{
      return "#" + cssEscape(node.id);
    }}
    const segments = [];
    let current = node;
    while (current && current.nodeType === Node.ELEMENT_NODE && current !== document.body) {{
      const tag = String(current.tagName || "").toLowerCase();
      if (!tag) {{
        break;
      }}
      let segment = tag;
      const parent = current.parentElement;
      if (parent) {{
        const sameTagSiblings = Array.from(parent.children).filter((child) => {{
          return String(child.tagName || "").toLowerCase() === tag;
        }});
        if (sameTagSiblings.length > 1) {{
          const position = sameTagSiblings.indexOf(current);
          segment += `:nth-of-type(${{position + 1}})`;
        }}
      }}
      segments.unshift(segment);
      current = parent;
      if (current && current.id) {{
        segments.unshift("#" + cssEscape(current.id));
        break;
      }}
    }}
    return segments.join(" > ") || null;
  }}

  function clickPoint(node) {{
    if (!node || typeof node.getBoundingClientRect !== "function") {{
      return {{ center_x: null, center_y: null }};
    }}
    const rect = node.getBoundingClientRect();
    if (!(rect.width > 0 && rect.height > 0)) {{
      return {{ center_x: null, center_y: null }};
    }}
    return {{
      center_x: Math.round(rect.left + rect.width / 2),
      center_y: Math.round(rect.top + rect.height / 2)
    }};
  }}

  function isBodyLikeTarget(target) {{
    if (!target || !target.tagName) {{
      return false;
    }}
    const tag = String(target.tagName || "").toLowerCase();
    return tag === "body" || tag === "html";
  }}

  function rememberPointerPosition(event) {{
    if (!event || typeof event.clientX !== "number" || typeof event.clientY !== "number") {{
      return;
    }}
    lastPointerPosition = {{
      x: Math.round(event.clientX),
      y: Math.round(event.clientY)
    }};
  }}

  function pointerMotionIsMeaningful(event) {{
    const target = event && event.target && event.target.nodeType === Node.ELEMENT_NODE
      ? event.target
      : null;
    if (event && typeof event.buttons === "number" && event.buttons > 0) {{
      return true;
    }}
    if (event && typeof event.movementX === "number" && event.movementX !== 0) {{
      return true;
    }}
    if (event && typeof event.movementY === "number" && event.movementY !== 0) {{
      return true;
    }}
    if (
      lastPointerPosition &&
      event &&
      typeof event.clientX === "number" &&
      typeof event.clientY === "number"
    ) {{
      return (
        lastPointerPosition.x !== Math.round(event.clientX) ||
        lastPointerPosition.y !== Math.round(event.clientY)
      );
    }}
    // Chromium can emit a hover/move event as soon as a new page appears under a
    // stationary cursor. Keep those startup transitions from counting as agent actions.
    return !isBodyLikeTarget(target) || Date.now() >= startupPointerNoiseGuardUntilMs;
  }}

  function shouldIgnorePointerTrigger(trigger, event) {{
    if (trigger === "mousemove") {{
      const meaningful = pointerMotionIsMeaningful(event);
      rememberPointerPosition(event);
      if (meaningful) {{
        pointerMotionArmed = true;
      }}
      return !meaningful;
    }}
    if (trigger === "mouseover" || trigger === "mouseout" || trigger === "mouseenter" || trigger === "mouseleave") {{
      rememberPointerPosition(event);
      return !pointerMotionArmed;
    }}
    if (trigger === "click" || trigger === "wheel") {{
      pointerMotionArmed = true;
      rememberPointerPosition(event);
    }}
    return false;
  }}

  function interactiveElements() {{
    const selector = [
      "a",
      "button",
      ".alink",
      "input",
      "select",
      "textarea",
      "label",
      "option",
      ".ui-menu-item",
      ".ui-menu-item-wrapper",
      "[role='option']"
    ].join(",");
    return Array.from(document.querySelectorAll(selector)).map((node) => {{
      const point = clickPoint(node);
      const selectedLabels = node.tagName && node.tagName.toLowerCase() === "select"
        ? Array.from(node.selectedOptions || []).map((option) => normalizeText(option.label || option.textContent))
        : [];
      return {{
        tag: (node.tagName || "").toLowerCase(),
        id: node.id || null,
        selector: selectorFor(node),
        center_x: point.center_x,
        center_y: point.center_y,
        name: node.getAttribute("name"),
        text: normalizeText(node.innerText || node.textContent || ""),
        value: node.value != null ? String(node.value) : null,
        input_type: node.getAttribute("type"),
        checked: typeof node.checked === "boolean" ? !!node.checked : null,
        selected_labels: selectedLabels,
        class_list: Array.from(node.classList || []),
        visible: isVisible(node),
        disabled: !!node.disabled
      }};
    }});
  }}

  function scrollTargets() {{
    const selector = ["textarea", "select", "div", "ul"].join(",");
    return Array.from(document.querySelectorAll(selector))
      .filter((node) => node.scrollHeight > (node.clientHeight + 4))
      .map((node) => {{
        const point = clickPoint(node);
        return {{
          tag: (node.tagName || "").toLowerCase(),
          id: node.id || null,
          selector: selectorFor(node),
          center_x: point.center_x,
          center_y: point.center_y,
          scroll_top: Number(node.scrollTop || 0),
          scroll_height: Number(node.scrollHeight || 0),
          client_height: Number(node.clientHeight || 0),
          value: node.value != null ? String(node.value) : normalizeText(node.textContent || "").slice(0, 4096)
        }};
      }});
  }}

  function domAttributes(node) {{
    const attributes = {{}};
    if (!node || !node.attributes) {{
      return attributes;
    }}
    const allowlisted = new Set([
      "id",
      "class",
      "name",
      "type",
      "value",
      "readonly",
      "aria-readonly",
      "disabled",
      "checked",
      "selected",
      "fill",
      "stroke",
      "font-size",
      "cx",
      "cy",
      "r",
      "x",
      "y",
      "width",
      "height",
      "points",
      "d",
      "viewBox"
    ]);
    const booleanAttributes = new Set([
      "readonly",
      "disabled",
      "checked",
      "selected"
    ]);
    for (const attr of Array.from(node.attributes)) {{
      const name = String(attr.name || "");
      if (!name) {{
        continue;
      }}
      if (!allowlisted.has(name) && !name.startsWith("data-")) {{
        continue;
      }}
      const rawValue = attr.value == null ? "" : String(attr.value);
      attributes[name] =
        rawValue || (booleanAttributes.has(name) ? "true" : "");
    }}
    return attributes;
  }}

  function domElements() {{
    const shapeTags = new Set([
      "svg",
      "g",
      "rect",
      "circle",
      "polygon",
      "path",
      "line",
      "ellipse",
      "text"
    ]);
    const elements = [];
    const seenSelectors = new Set();
    for (const node of Array.from(document.querySelectorAll("body *"))) {{
      if (elements.length >= 256) {{
        break;
      }}
      if (!node || !node.tagName || !isVisible(node)) {{
        continue;
      }}
      const tag = String(node.tagName || "").toLowerCase();
      if (!tag) {{
        continue;
      }}
      const selector = selectorFor(node);
      if (selector && seenSelectors.has(selector)) {{
        continue;
      }}
      const text = normalizeText(node.innerText || node.textContent || "");
      const attributes = domAttributes(node);
      const hasAttributes = Object.keys(attributes).length > 0;
      const isShape = shapeTags.has(tag);
      const isLeafText = text.length > 0 && (!node.children || node.children.length === 0);
      if (!isShape && !hasAttributes && !isLeafText) {{
        continue;
      }}
      const rect = node.getBoundingClientRect();
      const centerX = rect.left + (rect.width / 2);
      const centerY = rect.top + (rect.height / 2);
      elements.push({{
        tag,
        selector,
        text,
        visible: true,
        attributes,
        x: Number(rect.left || 0),
        y: Number(rect.top || 0),
        width: Number(rect.width || 0),
        height: Number(rect.height || 0),
        center_x: Number(centerX || 0),
        center_y: Number(centerY || 0)
      }});
      if (selector) {{
        seenSelectors.add(selector);
      }}
    }}
    return elements;
  }}

  function utterancePayload() {{
    try {{
      return core.getUtterance();
    }} catch (_err) {{
      return null;
    }}
  }}

  function utteranceText(payload) {{
    if (payload && typeof payload === "object" && payload.utterance != null) {{
      return String(payload.utterance);
    }}
    return payload == null ? "" : String(payload);
  }}

  function queryText() {{
    return normalizeText((document.getElementById("query") || {{ innerText: "" }}).innerText);
  }}

  function currentEpisodeId() {{
    const globalValue = Number(window.WOB_EPISODE_ID || 0);
    if (Number.isFinite(globalValue) && globalValue > 0) {{
      return globalValue;
    }}
    const node = document.getElementById("episode-id");
    const parsed = Number(node && node.textContent ? node.textContent : 0);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
  }}

  function captureStickyTerminalState() {{
    const sticky = {{
      terminated: true,
      reward: Number(window.WOB_REWARD_GLOBAL || 0),
      raw_reward: Number(window.WOB_RAW_REWARD_GLOBAL || 0),
      reason: window.WOB_REWARD_REASON == null ? null : String(window.WOB_REWARD_REASON),
      episode_id: currentEpisodeId(),
      utterance: utteranceText(utterancePayload()),
      query_text: queryText(),
      captured_at_ms: Date.now()
    }};
    window.__IOI_MINIWOB_STICKY_TERMINAL__ = sticky;
    return sticky;
  }}

  function stickyTerminalState() {{
    const sticky = window.__IOI_MINIWOB_STICKY_TERMINAL__;
    if (!sticky || !sticky.terminated) {{
      return null;
    }}
    const stickyEpisodeId = Number(sticky.episode_id || 0);
    if (!(stickyEpisodeId > 0)) {{
      return null;
    }}
    return currentEpisodeId() === stickyEpisodeId ? sticky : null;
  }}

  function fieldEntries(payload) {{
    if (!payload || typeof payload !== "object" || !payload.fields) {{
      return [];
    }}
    return Object.entries(payload.fields).map(([key, value]) => {{
      return {{ key, value: String(value) }};
    }});
  }}

  function buildState(trigger) {{
    const payload = utterancePayload();
    const active = document.activeElement || null;
    const currentReward = Number(window.WOB_REWARD_GLOBAL || 0);
    const currentRawReward = Number(window.WOB_RAW_REWARD_GLOBAL || 0);
    const currentTerminated = !!window.WOB_DONE_GLOBAL;
    if (currentTerminated) {{
      captureStickyTerminalState();
    }}
    const sticky = stickyTerminalState();
    const useStickyTerminal = !currentTerminated
      && sticky !== null
      && currentReward <= 0
      && currentRawReward <= 0;
    const effectiveUtterance = useStickyTerminal
      ? (sticky.utterance || utteranceText(payload))
      : utteranceText(payload);
    const effectiveReward = useStickyTerminal ? Number(sticky.reward || 0) : currentReward;
    const effectiveRawReward = useStickyTerminal
      ? Number(sticky.raw_reward || 0)
      : currentRawReward;
    const effectiveReason = useStickyTerminal
      ? (sticky.reason == null ? null : String(sticky.reason))
      : (window.WOB_REWARD_REASON == null ? null : String(window.WOB_REWARD_REASON));
    const effectiveQueryText = useStickyTerminal
      ? normalizeText(sticky.query_text || queryText())
      : queryText();
    return {{
      session_id: bridge.session_id,
      env_id: bridge.env_id,
      seed: bridge.seed,
      generation: bridge.generation,
      utterance: effectiveUtterance,
      reward: effectiveReward,
      terminated: currentTerminated || useStickyTerminal,
      truncated: false,
      episode_step: actionCounter,
      last_sync_ms: Date.now(),
      info: {{
        reason: effectiveReason,
        raw_reward: effectiveRawReward,
        query_text: effectiveQueryText,
        fields: fieldEntries(payload),
        page_url: window.location.href,
        task_ready: !!window.WOB_TASK_READY,
        focused_tag: active && active.tagName ? String(active.tagName).toLowerCase() : null,
        focused_id: active && active.id ? String(active.id) : null,
        last_event: lastEventSummary,
        visible_text_excerpt: normalizeText(document.body ? (document.body.innerText || document.body.textContent || "") : "").slice(0, 4096),
        interactive_elements: interactiveElements(),
        scroll_targets: scrollTargets(),
        dom_elements: domElements(),
        trigger: trigger
      }}
    }};
  }}

  async function postJson(path, payload) {{
    await fetch(path, {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify(payload)
    }});
  }}

  function scheduleSync(trigger) {{
    if (syncTimer !== null) {{
      window.clearTimeout(syncTimer);
    }}
    syncTimer = window.setTimeout(() => {{
      postJson(bridge.sync_url, buildState(trigger)).catch(() => null);
    }}, 60);
  }}

  function installTerminalStateHooks() {{
    if (!window.core || typeof window.core.endEpisode !== "function") {{
      return;
    }}
    if (window.__IOI_MINIWOB_TERMINAL_HOOKED__ === bridge.generation) {{
      return;
    }}
    const originalEndEpisode = window.core.endEpisode;
    window.__IOI_MINIWOB_TERMINAL_HOOKED__ = bridge.generation;
    window.core.endEpisode = function() {{
      const result = originalEndEpisode.apply(this, arguments);
      try {{
        captureStickyTerminalState();
      }} catch (_err) {{
        // ignore sticky capture failures and fall back to normal heartbeat sync
      }}
      postJson(bridge.sync_url, buildState("end_episode")).catch(() => null);
      return result;
    }};
  }}

  function startHeartbeat() {{
    if (heartbeatTimer !== null) {{
      window.clearInterval(heartbeatTimer);
    }}
    heartbeatTimer = window.setInterval(() => {{
      postJson(bridge.sync_url, buildState("heartbeat")).catch(() => null);
    }}, 120);
  }}

  function safeClick(node) {{
    if (!node) {{
      return false;
    }}
    try {{
      if (typeof node.click === "function") {{
        node.click();
        return true;
      }}
      node.dispatchEvent(new MouseEvent("click", {{ bubbles: true, cancelable: true }}));
      return true;
    }} catch (_err) {{
      return false;
    }}
  }}

  function findByText(targetText) {{
    const normalizedTarget = normalizeText(targetText);
    if (!normalizedTarget) {{
      return null;
    }}
    const selector = [
      "button",
      "a",
      "label",
      ".alink",
      ".ui-menu-item",
      ".ui-menu-item-wrapper",
      "[role='option']",
      "[href]"
    ].join(",");
    return Array.from(document.querySelectorAll(selector)).find((node) => {{
      return isVisible(node) && normalizeText(node.innerText || node.textContent || "") === normalizedTarget;
    }}) || null;
  }}

  function focusSelector(selector) {{
    const node = document.querySelector(selector);
    if (!node) {{
      return false;
    }}
    if (typeof node.focus === "function") {{
      node.focus();
    }}
    return true;
  }}

  function typeSelector(selector, text, replace) {{
    const node = document.querySelector(selector);
    if (!node) {{
      return false;
    }}
    if (typeof node.focus === "function") {{
      node.focus();
    }}
    if (replace) {{
      node.value = "";
    }}
    node.value = replace ? String(text || "") : String(node.value || "") + String(text || "");
    try {{
      node.dispatchEvent(new Event("input", {{ bubbles: true }}));
      node.dispatchEvent(new Event("change", {{ bubbles: true }}));
    }} catch (_err) {{}}
    return true;
  }}

  function selectLabel(selector, label) {{
    const node = document.querySelector(selector);
    if (!node || String(node.tagName || "").toLowerCase() !== "select") {{
      return false;
    }}
    const normalized = normalizeText(label);
    const options = Array.from(node.options || []);
    const index = options.findIndex((option) => normalizeText(option.label || option.textContent || option.value || "") === normalized);
    if (index < 0) {{
      return false;
    }}
    node.selectedIndex = index;
    try {{
      node.dispatchEvent(new Event("input", {{ bubbles: true }}));
      node.dispatchEvent(new Event("change", {{ bubbles: true }}));
    }} catch (_err) {{}}
    return true;
  }}

  function scrollTarget(selector, position) {{
    const node = document.querySelector(selector);
    if (!node) {{
      return false;
    }}
    if (position === "top") {{
      node.scrollTop = 0;
    }} else if (position === "bottom") {{
      node.scrollTop = node.scrollHeight;
    }}
    return true;
  }}

  async function executeOracleCommand(command) {{
    let ok = false;
    const args = command.arguments || {{}};
    switch (command.type) {{
      case "click_selector":
        ok = safeClick(document.querySelector(args.selector || ""));
        break;
      case "click_text":
        ok = safeClick(findByText(args.text || ""));
        break;
      case "focus_selector":
        ok = focusSelector(args.selector || "");
        break;
      case "type_selector":
        ok = typeSelector(args.selector || "", args.text || "", args.replace !== false);
        break;
      case "select_label":
        ok = selectLabel(args.selector || "", args.label || "");
        break;
      case "scroll_target":
        ok = scrollTarget(args.selector || "", args.position || "bottom");
        break;
      default:
        ok = false;
        break;
    }}
    actionCounter += 1;
    await postJson(bridge.sync_url, buildState("oracle:" + command.type + ":" + ok)).catch(() => null);
  }}

  async function pollOracle() {{
    try {{
      const response = await fetch(bridge.oracle_poll_url + "?generation=" + bridge.generation + "&after=" + lastOracleSeq);
      if (response.ok) {{
        const payload = await response.json();
        if (payload.command && payload.command.seq > lastOracleSeq) {{
          lastOracleSeq = payload.command.seq;
          await executeOracleCommand(payload.command);
        }}
      }}
    }} catch (_err) {{
      // ignore bridge polling errors and keep trying
    }}
    window.setTimeout(pollOracle, 100);
  }}

  function installEventHooks() {{
    const summarizeEvent = (trigger, event) => {{
      const target = event && event.target && event.target.nodeType === Node.ELEMENT_NODE
        ? event.target
        : null;
      const point = clickPoint(target);
      lastEventSummary = {{
        kind: trigger,
        timestamp_ms: Date.now(),
        target_selector: selectorFor(target),
        target_tag: target && target.tagName ? String(target.tagName).toLowerCase() : null,
        target_id: target && target.id ? String(target.id) : null,
        x: event && typeof event.clientX === "number" ? Math.round(event.clientX) : point.center_x,
        y: event && typeof event.clientY === "number" ? Math.round(event.clientY) : point.center_y
      }};
    }};
    const bump = (trigger, event, minIntervalMs = 0) => {{
      if (shouldIgnorePointerTrigger(trigger, event)) {{
        return;
      }}
      summarizeEvent(trigger, event);
      const now = Date.now();
      if (minIntervalMs > 0 && (now - lastMoveSyncMs) < minIntervalMs) {{
        return;
      }}
      if (minIntervalMs > 0) {{
        lastMoveSyncMs = now;
      }}
      actionCounter += 1;
      scheduleSync(trigger);
    }};
    window.addEventListener("click", (event) => bump("click", event), true);
    window.addEventListener("change", (event) => bump("change", event), true);
    window.addEventListener("keydown", (event) => bump("keydown", event), true);
    window.addEventListener("wheel", (event) => bump("wheel", event), true);
    window.addEventListener("mousemove", (event) => bump("mousemove", event, 80), true);
    window.addEventListener("mouseover", (event) => bump("mouseover", event), true);
    window.addEventListener("mouseout", (event) => bump("mouseout", event), true);
    window.addEventListener("mouseenter", (event) => bump("mouseenter", event), true);
    window.addEventListener("mouseleave", (event) => bump("mouseleave", event), true);
  }}

  function startTask() {{
    try {{
      startupPointerNoiseGuardUntilMs = Date.now() + 120;
      if (window.Math && typeof window.Math.seedrandom === "function") {{
        window.Math.seedrandom(String(bridge.seed));
      }}
      if (window.core && typeof window.core.setDataMode === "function") {{
        window.core.setDataMode(bridge.data_mode);
      }}
      if (window.core && typeof window.core.startEpisodeReal === "function") {{
        installTerminalStateHooks();
        window.core.startEpisodeReal();
      }}
      installEventHooks();
      startHeartbeat();
      postJson(bridge.sync_url, buildState("bootstrap")).catch(() => null);
      pollOracle();
    }} catch (_err) {{
      postJson(bridge.sync_url, {{
        session_id: bridge.session_id,
        env_id: bridge.env_id,
        seed: bridge.seed,
        generation: bridge.generation,
        utterance: "",
        reward: 0,
        terminated: false,
        truncated: false,
        episode_step: actionCounter,
        last_sync_ms: Date.now(),
        info: {{
          reason: "bootstrap_failed",
          raw_reward: 0,
          query_text: "",
          fields: [],
          page_url: window.location.href,
          task_ready: false,
          focused_tag: null,
          focused_id: null,
          visible_text_excerpt: "",
          interactive_elements: [],
          scroll_targets: [],
          dom_elements: []
        }}
      }}).catch(() => null);
    }}
  }}

  window.addEventListener("load", function() {{
    window.setTimeout(startTask, 20);
  }});
  window.addEventListener("beforeunload", function() {{
    if (heartbeatTimer !== null) {{
      window.clearInterval(heartbeatTimer);
    }}
    navigator.sendBeacon(bridge.sync_url, JSON.stringify(buildState("beforeunload")));
  }});
}})();
</script>
"""


class Session:
    def __init__(self, html_root: Path, env_id: str, seed: int, data_mode: str, host_url: str):
        self.session_id = secrets.token_hex(8)
        self.env_id = env_id
        self.task_name = _normalize_env_id(env_id)
        self.seed = int(seed)
        self.data_mode = data_mode
        self.host_url = host_url.rstrip("/")
        self.html_root = html_root
        self.root_dir = SESSION_ROOT / self.session_id
        self.generation = 0
        self.last_state: Dict[str, Any] = {
            "session_id": self.session_id,
            "env_id": self.env_id,
            "seed": self.seed,
            "utterance": "",
            "reward": 0.0,
            "terminated": False,
            "truncated": False,
            "episode_step": 0,
            "generation": self.generation,
            "last_sync_ms": None,
            "info": {
                "reason": None,
                "raw_reward": 0.0,
                "query_text": None,
                "fields": [],
                "page_url": None,
                "task_ready": False,
                "focused_tag": None,
                "focused_id": None,
                "visible_text_excerpt": None,
                "interactive_elements": [],
                "scroll_targets": [],
                "dom_elements": [],
            },
        }
        self._commands: list[Dict[str, Any]] = []
        self._next_command_seq = 1
        self._next_sync_index = 0
        self._closed = False
        self.sync_history: list[Dict[str, Any]] = []
        self._rebuild_session_files()

    def _task_html_path(self) -> Path:
        return self.html_root / "miniwob" / f"{self.task_name}.html"

    def _ensure_root_dirs(self) -> None:
        self.root_dir.mkdir(parents=True, exist_ok=True)
        for name in ("core", "common", "flight"):
            source = self.html_root / name
            target = self.root_dir / name
            if target.exists() or target.is_symlink():
                continue
            if source.exists():
                target.symlink_to(source, target_is_directory=True)
        (self.root_dir / "miniwob").mkdir(exist_ok=True)

    def _rebuild_session_files(self) -> None:
        task_html_path = self._task_html_path()
        if not task_html_path.is_file():
            raise RuntimeError(f"MiniWoB task HTML missing for {self.env_id}: {task_html_path}")

        self.generation += 1
        self._ensure_root_dirs()
        instrumented_path = self.root_dir / "miniwob" / f"{self.task_name}.{self.generation}.html"
        html = task_html_path.read_text(encoding="utf-8")
        config = {
            "session_id": self.session_id,
            "env_id": self.env_id,
            "seed": self.seed,
            "generation": self.generation,
            "data_mode": self.data_mode,
            "sync_url": f"{self.host_url}/session/{self.session_id}/sync",
            "oracle_poll_url": f"{self.host_url}/session/{self.session_id}/oracle_poll",
        }
        injected = _js_instrumentation(config)
        if "</body>" in html:
            html = html.replace("</body>", injected + "\n</body>")
        else:
            html += injected
        instrumented_path.write_text(html, encoding="utf-8")
        self.last_state.update(
            {
                "seed": self.seed,
                "generation": self.generation,
                "episode_step": 0,
                "terminated": False,
                "truncated": False,
                "reward": 0.0,
                "utterance": "",
                "last_sync_ms": None,
                "sync_history": [],
                "info": {
                    "reason": None,
                    "raw_reward": 0.0,
                    "query_text": None,
                    "fields": [],
                    "page_url": instrumented_path.resolve().as_uri(),
                    "task_ready": False,
                    "focused_tag": None,
                    "focused_id": None,
                    "last_event": None,
                    "visible_text_excerpt": None,
                    "interactive_elements": [],
                    "scroll_targets": [],
                    "dom_elements": [],
                    "trigger": None,
                },
            }
        )
        self.sync_history = []
        self._next_sync_index = 0
        self._commands = []
        self._next_command_seq = 1

    @property
    def url(self) -> str:
        return self.last_state["info"]["page_url"]

    def to_public_state(self) -> Dict[str, Any]:
        return dict(self.last_state)

    def reset(self, seed: Optional[int], data_mode: Optional[str]) -> Dict[str, Any]:
        if seed is not None:
            self.seed = int(seed)
        if data_mode:
            self.data_mode = data_mode
        self._rebuild_session_files()
        return self.to_public_state()

    @staticmethod
    def _compact_sync_text(value: Any) -> Optional[str]:
        if value is None:
            return None
        text = " ".join(str(value).split())
        if not text:
            return None
        if len(text) <= SYNC_HISTORY_TEXT_LIMIT:
            return text
        return text[: SYNC_HISTORY_TEXT_LIMIT - 3] + "..."

    def _sync_record(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        info = payload.get("info", {})
        if not isinstance(info, dict):
            info = {}
        interactive_elements = info.get("interactive_elements", [])
        scroll_targets = info.get("scroll_targets", [])
        dom_elements = info.get("dom_elements", [])
        return {
            "sync_index": self._next_sync_index,
            "last_sync_ms": payload.get("last_sync_ms"),
            "episode_step": payload.get("episode_step"),
            "reward": payload.get("reward"),
            "raw_reward": info.get("raw_reward"),
            "terminated": payload.get("terminated"),
            "truncated": payload.get("truncated"),
            "trigger": info.get("trigger"),
            "reason": info.get("reason"),
            "query_text": self._compact_sync_text(info.get("query_text")),
            "visible_text_excerpt": self._compact_sync_text(info.get("visible_text_excerpt")),
            "focused_tag": info.get("focused_tag"),
            "focused_id": info.get("focused_id"),
            "last_event": info.get("last_event"),
            "page_url": info.get("page_url"),
            "interactive_count": len(interactive_elements)
            if isinstance(interactive_elements, list)
            else 0,
            "scroll_target_count": len(scroll_targets) if isinstance(scroll_targets, list) else 0,
            "dom_count": len(dom_elements) if isinstance(dom_elements, list) else 0,
        }

    def _append_sync_history(self, payload: Dict[str, Any]) -> None:
        self.sync_history.append(self._sync_record(payload))
        self._next_sync_index += 1
        if len(self.sync_history) > SYNC_HISTORY_LIMIT:
            self.sync_history = self.sync_history[-SYNC_HISTORY_LIMIT:]

    def update_state(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if int(payload.get("generation", 0)) != self.generation:
            return self.to_public_state()
        if self.last_state.get("terminated") or self.last_state.get("truncated"):
            return self.to_public_state()
        payload["session_id"] = self.session_id
        payload["env_id"] = self.env_id
        payload["seed"] = self.seed
        payload["generation"] = self.generation
        self._append_sync_history(payload)
        payload["sync_history"] = list(self.sync_history)
        self.last_state = payload
        return self.to_public_state()

    def enqueue_oracle(self, command_type: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        command = {
            "seq": self._next_command_seq,
            "generation": self.generation,
            "type": command_type,
            "arguments": arguments,
            "issued_at_ms": _now_ms(),
        }
        self._next_command_seq += 1
        self._commands.append(command)
        return command

    def next_oracle(self, generation: int, after: int) -> Optional[Dict[str, Any]]:
        for command in self._commands:
            if command["generation"] != generation:
                continue
            if int(command["seq"]) > after:
                return command
        return None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        shutil.rmtree(self.root_dir, ignore_errors=True)


class BridgeState:
    def __init__(self, html_root: Path, host_url: str):
        self.html_root = html_root
        self.host_url = host_url
        self.lock = threading.RLock()
        self.sessions: Dict[str, Session] = {}

    def create_session(self, env_id: str, seed: int, data_mode: str) -> Session:
        with self.lock:
            session = Session(self.html_root, env_id, seed, data_mode, self.host_url)
            self.sessions[session.session_id] = session
            return session

    def get_session(self, session_id: str) -> Session:
        with self.lock:
            session = self.sessions.get(session_id)
            if session is None:
                raise KeyError(session_id)
            return session

    def close_all(self) -> None:
        with self.lock:
            for session in list(self.sessions.values()):
                session.close()
            self.sessions.clear()


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "IOIMiniWoBBridge/1.0"

    @property
    def bridge(self) -> BridgeState:
        return self.server.bridge_state  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = _json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _parse_session_path(self) -> tuple[Optional[str], Optional[str]]:
        parts = [part for part in self.path.split("?")[0].split("/") if part]
        if len(parts) >= 3 and parts[0] == "session":
            return parts[1], parts[2]
        return None, None

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send_json(HTTPStatus.OK, {"ok": True})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "html_root": str(self.bridge.html_root),
                    "session_count": len(self.bridge.sessions),
                },
            )
            return

        session_id, action = self._parse_session_path()
        if not session_id or not action:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return

        try:
            session = self.bridge.get_session(session_id)
        except KeyError:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "session_not_found"})
            return

        if action == "state":
            self._send_json(HTTPStatus.OK, session.to_public_state())
            return
        if action == "url":
            self._send_json(HTTPStatus.OK, {"url": session.url, "generation": session.generation})
            return
        if action == "oracle_poll":
            query = parse_qs(parsed.query)
            generation = int(query.get("generation", [str(session.generation)])[0])
            after = int(query.get("after", ["0"])[0])
            self._send_json(
                HTTPStatus.OK,
                {"command": session.next_oracle(generation, after)},
            )
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/session/create":
            payload = self._read_json_body()
            env_id = str(payload.get("env_id", "")).strip()
            if not env_id:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "env_id_required"})
                return
            seed = int(payload.get("seed", 0))
            data_mode = str(payload.get("data_mode", "train") or "train")
            session = self.bridge.create_session(env_id=env_id, seed=seed, data_mode=data_mode)
            self._send_json(
                HTTPStatus.OK,
                {
                    "session_id": session.session_id,
                    "url": session.url,
                    "state": session.to_public_state(),
                },
            )
            return

        session_id, action = self._parse_session_path()
        if not session_id or not action:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return

        try:
            session = self.bridge.get_session(session_id)
        except KeyError:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "session_not_found"})
            return

        payload = self._read_json_body()
        if action == "reset":
            state = session.reset(
                seed=payload.get("seed"),
                data_mode=payload.get("data_mode"),
            )
            self._send_json(
                HTTPStatus.OK,
                {"session_id": session.session_id, "url": session.url, "state": state},
            )
            return
        if action == "sync":
            state = session.update_state(payload)
            self._send_json(HTTPStatus.OK, {"ok": True, "state": state})
            return
        if action == "oracle_step":
            command_type = str(payload.get("type", "")).strip()
            if not command_type:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "oracle_type_required"})
                return
            arguments = payload.get("arguments", {})
            if not isinstance(arguments, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "oracle_arguments_invalid"})
                return
            command = session.enqueue_oracle(command_type, arguments)
            self._send_json(HTTPStatus.OK, {"ok": True, "command": command})
            return
        if action == "close":
            session.close()
            with self.bridge.lock:
                self.bridge.sessions.pop(session.session_id, None)
            self._send_json(HTTPStatus.OK, {"ok": True})
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})


def _cleanup(state: BridgeState) -> None:
    state.close_all()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    html_root = _discover_html_root()
    SESSION_ROOT.mkdir(parents=True, exist_ok=True)
    host_url = f"http://{args.host}:{args.port}"
    bridge_state = BridgeState(html_root=html_root, host_url=host_url)
    atexit.register(_cleanup, bridge_state)

    server = ThreadingHTTPServer((args.host, args.port), BridgeHandler)
    server.bridge_state = bridge_state  # type: ignore[attr-defined]

    print(
        json.dumps(
            {
                "bridge": "ready",
                "host": args.host,
                "port": args.port,
                "html_root": str(html_root),
            }
        ),
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        bridge_state.close_all()
    return 0


if __name__ == "__main__":
    sys.exit(main())
