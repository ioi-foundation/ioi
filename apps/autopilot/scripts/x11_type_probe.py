#!/usr/bin/env python3
import argparse
import sys
import time
from typing import Optional

from Xlib import X, XK, display, error
from Xlib.ext import xtest


def get_window_name(win) -> Optional[str]:
    try:
        wm_name = win.get_wm_name()
        if wm_name:
            return wm_name
    except error.XError:
        return None
    return None


def find_window_by_title(root, title: str):
    stack = [root]
    while stack:
        win = stack.pop()
        name = get_window_name(win)
        if name == title:
            return win
        try:
            children = win.query_tree().children
        except error.XError:
            continue
        stack.extend(children)
    return None


def tap_key(disp: display.Display, keysym: int) -> None:
    keycode = disp.keysym_to_keycode(keysym)
    if keycode == 0:
        return
    xtest.fake_input(disp, X.KeyPress, keycode)
    xtest.fake_input(disp, X.KeyRelease, keycode)


def type_ascii_text(disp: display.Display, text: str, delay_ms: int) -> None:
    for ch in text:
        keysym = XK.string_to_keysym(ch)
        if keysym == 0:
            continue
        tap_key(disp, keysym)
        disp.sync()
        time.sleep(delay_ms / 1000.0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Send ASCII text to a focused X11 window.")
    parser.add_argument("--title", default="Autopilot", help="Exact window title to target")
    parser.add_argument("--text", required=True, help="ASCII text to type")
    parser.add_argument("--press-enter", action="store_true", help="Press Enter after typing")
    parser.add_argument("--startup-timeout", type=float, default=10.0)
    parser.add_argument("--char-delay-ms", type=int, default=25)
    args = parser.parse_args()

    disp = display.Display()
    root = disp.screen().root

    deadline = time.time() + args.startup_timeout
    target = None
    while time.time() < deadline:
        target = find_window_by_title(root, args.title)
        if target is not None:
            break
        time.sleep(0.1)

    if target is None:
        print(f"Window '{args.title}' not found before timeout", file=sys.stderr)
        return 2

    try:
        target.configure(stack_mode=X.Above)
        target.set_input_focus(X.RevertToParent, X.CurrentTime)
        disp.sync()
    except error.XError as exc:
        print(f"Failed to focus target window: {exc}", file=sys.stderr)
        return 3

    # Give compositor + webview a short settle window before injecting.
    time.sleep(0.25)
    type_ascii_text(disp, args.text, args.char_delay_ms)
    if args.press_enter:
        tap_key(disp, XK.string_to_keysym("Return"))
    disp.sync()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
