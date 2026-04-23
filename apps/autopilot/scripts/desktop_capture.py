#!/usr/bin/env python3
"""Shared capture helpers for Linux desktop probes.

These probes primarily exercise the real Tauri desktop shell, but on some
Linux/X11 WebKit stacks a per-window capture can intermittently come back as a
uniform black image even when the UI is visible. To keep parity probes
deterministic, we detect obviously blank captures and can fall back to a
headless browser screenshot of the matching Vite route.
"""

from __future__ import annotations

from dataclasses import dataclass
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_BLANK_STDDEV_THRESHOLD = 0.0001


@dataclass
class CaptureResult:
    error: str | None
    mode: str
    diagnostics: dict[str, Any]


def _run(
    cmd: list[str],
    *,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _capture_with_import(window_id: int, output_path: Path, *, timeout_secs: float) -> str | None:
    try:
        completed = _run(
            ["import", "-window", str(window_id), str(output_path)],
            timeout=timeout_secs,
        )
    except subprocess.TimeoutExpired:
        return f"Timed out capturing window {window_id}"

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        return stderr or f"Window capture exited with {completed.returncode}"
    return None


def _analyze_capture(output_path: Path) -> dict[str, float | int | str] | None:
    identify = shutil.which("identify")
    if identify is None or not output_path.exists():
        return None

    completed = _run(
        [
            identify,
            "-format",
            "%k %[fx:mean] %[fx:standard_deviation]",
            str(output_path),
        ]
    )
    if completed.returncode != 0:
        return None

    parts = completed.stdout.strip().split()
    if len(parts) != 3:
        return None

    try:
        return {
            "unique_colors": int(parts[0]),
            "mean": float(parts[1]),
            "stddev": float(parts[2]),
        }
    except ValueError:
        return None


def _blank_capture_reason(output_path: Path) -> str | None:
    analysis = _analyze_capture(output_path)
    if analysis is None:
        return None

    unique_colors = int(analysis["unique_colors"])
    stddev = float(analysis["stddev"])
    if unique_colors <= 1:
        return f"uniform image (unique_colors={unique_colors}, stddev={stddev:.6f})"
    if stddev <= DEFAULT_BLANK_STDDEV_THRESHOLD:
        return f"near-uniform image (unique_colors={unique_colors}, stddev={stddev:.6f})"
    return None


def _capture_with_firefox(browser_url: str, output_path: Path, *, timeout_secs: float) -> str | None:
    firefox = shutil.which("firefox")
    if firefox is None:
        return "Firefox is not installed for browser fallback captures"

    profile_dir = Path(tempfile.mkdtemp(prefix="autopilot-capture-firefox-"))
    try:
        try:
            completed = _run(
                [
                    firefox,
                    "--headless",
                    "--profile",
                    str(profile_dir),
                    "--screenshot",
                    str(output_path),
                    browser_url,
                ],
                timeout=timeout_secs,
            )
        except subprocess.TimeoutExpired:
            return f"Timed out capturing browser fallback for {browser_url}"

        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            return stderr or f"Browser fallback capture exited with {completed.returncode}"
        return None
    finally:
        shutil.rmtree(profile_dir, ignore_errors=True)


def capture_window_with_fallback(
    window_id: int,
    output_path: Path,
    *,
    browser_url: str | None = None,
    timeout_secs: float = 8.0,
) -> CaptureResult:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    diagnostics: dict[str, Any] = {
        "window_id": window_id,
        "browser_fallback_url": browser_url,
    }

    window_error = _capture_with_import(window_id, output_path, timeout_secs=timeout_secs)
    if window_error is None:
        diagnostics["window_analysis"] = _analyze_capture(output_path)
        blank_reason = _blank_capture_reason(output_path)
        if blank_reason is None:
            return CaptureResult(
                error=None,
                mode="window",
                diagnostics=diagnostics,
            )
        window_error = f"Window capture looked blank: {blank_reason}"
        diagnostics["window_blank_reason"] = blank_reason
    else:
        diagnostics["window_capture_error"] = window_error

    if not browser_url:
        return CaptureResult(
            error=window_error,
            mode="window-error",
            diagnostics=diagnostics,
        )

    browser_error = _capture_with_firefox(
        browser_url,
        output_path,
        timeout_secs=max(timeout_secs, 20.0),
    )
    if browser_error is None:
        diagnostics["browser_analysis"] = _analyze_capture(output_path)
        blank_reason = _blank_capture_reason(output_path)
        if blank_reason is None:
            diagnostics["window_capture_error"] = window_error
            return CaptureResult(
                error=None,
                mode="browser-fallback",
                diagnostics=diagnostics,
            )
        browser_error = f"Browser fallback looked blank: {blank_reason}"
        diagnostics["browser_blank_reason"] = blank_reason
    else:
        diagnostics["browser_capture_error"] = browser_error

    return CaptureResult(
        error=browser_error,
        mode="browser-fallback-error",
        diagnostics=diagnostics,
    )
