#!/usr/bin/env python3
import argparse
import base64
import importlib
import json
import os
import pickle
import sys
from pathlib import Path
from urllib.parse import urlparse


def emit(payload):
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def _prepend_pythonpath(root_env, suffix):
    root = os.environ.get(root_env, "").strip()
    if not root:
        return None
    candidate = Path(root).expanduser() / suffix
    if candidate.exists():
        sys.path.insert(0, str(candidate))
        return str(candidate)
    return None


def configure_source_overrides():
    configured = {}
    browsergym_core = _prepend_pythonpath("IOI_BROWSERGYM_SOURCE_ROOT", "browsergym/core/src")
    if browsergym_core:
        configured["browsergym_core"] = browsergym_core
    workarena_source = _prepend_pythonpath("IOI_WORKARENA_SOURCE_ROOT", "src")
    if workarena_source:
        configured["workarena"] = workarena_source
    return configured


def direct_instance_credentials_present():
    required = ("SNOW_INSTANCE_URL", "SNOW_INSTANCE_UNAME", "SNOW_INSTANCE_PWD")
    return all(os.environ.get(key, "").strip() for key in required)


def ensure_instance_xor_seed():
    existing = os.environ.get("INSTANCE_XOR_SEED", "").strip()
    if existing:
        return {"present": True, "auto_seeded": False}
    if direct_instance_credentials_present():
        os.environ["INSTANCE_XOR_SEED"] = "ioi-direct-instance-placeholder-seed"
        return {"present": True, "auto_seeded": True}
    return {"present": False, "auto_seeded": False}


def import_status(module_name):
    try:
        importlib.import_module(module_name)
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}


def import_workarena():
    configure_source_overrides()
    ensure_instance_xor_seed()
    return importlib.import_module("browsergym.workarena")


def bridge_preflight():
    source_overrides = configure_source_overrides()
    xor_seed_status = ensure_instance_xor_seed()
    requirements = {
        "playwright": import_status("playwright"),
        "browsergym.workarena": import_status("browsergym.workarena"),
        "requests": import_status("requests"),
        "huggingface_hub": import_status("huggingface_hub"),
        "numpy": import_status("numpy"),
        "gymnasium": import_status("gymnasium"),
    }

    env = {
        "instance_xor_seed_present": xor_seed_status["present"],
        "instance_xor_seed_auto_seeded": xor_seed_status["auto_seeded"],
        "snow_instance_direct_credentials": direct_instance_credentials_present(),
        "snow_instance_pool": bool(os.environ.get("SNOW_INSTANCE_POOL", "").strip()),
        "hugging_face_hub_token": bool(
            os.environ.get("HUGGING_FACE_HUB_TOKEN", "").strip()
            or os.environ.get("HF_TOKEN", "").strip()
        ),
    }

    blockers = []
    if not requirements["playwright"]["ok"]:
        blockers.append("missing playwright python package")
    if not requirements["browsergym.workarena"]["ok"]:
        blockers.append("missing or unusable browsergym-workarena package")
    if not env["instance_xor_seed_present"]:
        blockers.append("missing INSTANCE_XOR_SEED for WorkArena instance access")
    if not (
        env["snow_instance_direct_credentials"]
        or env["snow_instance_pool"]
        or env["hugging_face_hub_token"]
    ):
        blockers.append(
            "missing ServiceNow instance credentials or Hugging Face access for WorkArena instances"
        )

    payload = {
        "benchmark": "workarena",
        "bridge": "cdp",
        "ok": not blockers,
        "blockers": blockers,
        "env": env,
        "python": sys.version.split()[0],
        "requirements": requirements,
        "source_overrides": source_overrides,
    }
    emit(payload)
    return 0 if not blockers else 2


def connect_over_cdp(cdp_url):
    from playwright.sync_api import sync_playwright

    parsed = urlparse(cdp_url)
    candidates = [cdp_url]
    if parsed.scheme in ("ws", "wss") and parsed.hostname and parsed.port:
        candidates.append(f"http://{parsed.hostname}:{parsed.port}")
        candidates.append(f"https://{parsed.hostname}:{parsed.port}")

    pw = sync_playwright().start()
    last_error = None
    for endpoint in candidates:
        try:
            browser = pw.chromium.connect_over_cdp(endpoint)
            return pw, browser
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

    pw.stop()
    raise RuntimeError(
        f"failed to connect to CDP endpoint candidates={candidates}: {last_error}"
    )


def resolve_existing_page(browser):
    for context in reversed(browser.contexts):
        if context.pages:
            return context.pages[-1]
    raise RuntimeError("no existing page available in CDP-attached browser")


def load_task_class(task_id):
    workarena = import_workarena()
    for task_class in getattr(workarena, "ALL_WORKARENA_TASKS", []):
        if task_class.get_task_id() == task_id:
            return task_class
    available = sorted(task.get_task_id() for task in getattr(workarena, "ALL_WORKARENA_TASKS", []))
    raise RuntimeError(
        f"unknown WorkArena task_id='{task_id}'. available_task_count={len(available)}"
    )


def freeze_task(task):
    page = getattr(task, "page", None)
    if page is not None:
        task.page = None
    try:
        return base64.b64encode(pickle.dumps(task)).decode("ascii")
    finally:
        if page is not None:
            task.page = page


def thaw_task(encoded):
    return pickle.loads(base64.b64decode(encoded.encode("ascii")))


def prepare_task(args):
    state_path = Path(args.state_path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    task_class = load_task_class(args.task_id)
    pw, browser = connect_over_cdp(args.cdp_url)
    try:
        page = resolve_existing_page(browser)
        task = task_class(seed=args.seed)
        goal, info = task.setup(page=page)
        state_payload = {
            "task_id": args.task_id,
            "seed": args.seed,
            "goal": goal,
            "info": info,
            "start_url": getattr(task, "start_url", ""),
            "final_url": getattr(task, "final_url", ""),
            "task_pickle_b64": freeze_task(task),
        }
        state_path.write_text(json.dumps(state_payload, indent=2, sort_keys=True), encoding="utf-8")
        emit(
            {
                "ok": True,
                "benchmark": "workarena",
                "task_id": args.task_id,
                "seed": args.seed,
                "goal": goal,
                "info": info,
                "page_url": page.url,
                "start_url": getattr(task, "start_url", ""),
                "final_url": getattr(task, "final_url", ""),
                "state_path": str(state_path),
            }
        )
        return 0
    finally:
        pw.stop()


def validate_task(args):
    state_payload = json.loads(Path(args.state_path).read_text(encoding="utf-8"))
    task = thaw_task(state_payload["task_pickle_b64"])
    pw, browser = connect_over_cdp(args.cdp_url)
    try:
        page = resolve_existing_page(browser)
        assistant_message = args.assistant_message.strip()
        chat_messages = []
        if assistant_message:
            chat_messages.append({"role": "assistant", "message": assistant_message})
        reward, done, message, info = task.validate(page=page, chat_messages=chat_messages)
        emit(
            {
                "ok": True,
                "benchmark": "workarena",
                "task_id": state_payload["task_id"],
                "seed": state_payload["seed"],
                "reward": reward,
                "done": done,
                "message": message,
                "info": info,
                "page_url": page.url,
            }
        )
        return 0
    finally:
        pw.stop()


def build_parser():
    parser = argparse.ArgumentParser(
        description="Bridge WorkArena setup/validation onto an existing BrowserDriver CDP session."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("preflight", help="Check benchmark dependencies and external access.")

    prepare = subparsers.add_parser(
        "prepare",
        help="Attach to the existing browser, setup a WorkArena task, and persist task state.",
    )
    prepare.add_argument("--cdp-url", required=True)
    prepare.add_argument("--task-id", required=True)
    prepare.add_argument("--seed", type=int, default=0)
    prepare.add_argument("--state-path", required=True)

    validate = subparsers.add_parser(
        "validate",
        help="Attach to the existing browser and validate a previously prepared WorkArena task.",
    )
    validate.add_argument("--cdp-url", required=True)
    validate.add_argument("--state-path", required=True)
    validate.add_argument("--assistant-message", default="")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "preflight":
            return bridge_preflight()
        if args.command == "prepare":
            return prepare_task(args)
        if args.command == "validate":
            return validate_task(args)
        raise RuntimeError(f"unsupported command: {args.command}")
    except Exception as exc:
        emit(
            {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
