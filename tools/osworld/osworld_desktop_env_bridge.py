#!/usr/bin/env python3
import argparse
import importlib
import importlib.util
import json
import os
import re
import shutil
import sys
from pathlib import Path


def emit(payload):
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def configure_source_overrides():
    configured = {}
    root = os.environ.get("IOI_OSWORLD_SOURCE_ROOT", "").strip()
    if not root:
        return configured

    root_path = Path(root).expanduser()
    candidates = []
    if (root_path / "desktop_env").exists():
        candidates.append(root_path)
    if root_path.name == "desktop_env" and root_path.parent.exists():
        candidates.append(root_path.parent)

    for candidate in candidates:
        sys.path.insert(0, str(candidate))
        configured["osworld"] = str(candidate)
        break

    return configured


def import_status(module_name):
    try:
        importlib.import_module(module_name)
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}


def discoverable_module_status(module_name):
    top_level = module_name.split(".", 1)[0]
    try:
        spec = importlib.util.find_spec(top_level)
    except Exception as exc:
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}

    if spec is None:
        return {"ok": False, "detail": f"top-level module '{top_level}' not found"}

    origin = getattr(spec, "origin", None)
    search_locations = getattr(spec, "submodule_search_locations", None)
    return {
        "ok": True,
        "top_level": top_level,
        "origin": str(origin) if origin else None,
        "search_locations": [str(path) for path in search_locations or []],
    }


def missing_dependency_name(detail):
    if not detail:
        return None
    match = re.search(r"No module named '([^']+)'", detail)
    if not match:
        return None
    return match.group(1)


def python_version_status():
    version = sys.version_info
    return {
        "ok": (version.major, version.minor) >= (3, 10),
        "version": f"{version.major}.{version.minor}.{version.micro}",
    }


def command_status(command_name):
    path = shutil.which(command_name)
    return {"ok": bool(path), "path": path}


def kvm_support_status():
    if not sys.platform.startswith("linux"):
        return {"checked": False, "supported": None}
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.is_file():
        return {"checked": True, "supported": None}
    try:
        text = cpuinfo.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {"checked": True, "supported": None}
    supported = ("vmx" in text) or ("svm" in text)
    return {"checked": True, "supported": supported}


def provider_command_statuses():
    return {
        "docker": command_status("docker"),
        "vmware": command_status("vmrun"),
        "virtualbox": command_status("VBoxManage"),
    }


def resolve_provider(explicit_provider=None):
    provider = (explicit_provider or os.environ.get("IOI_OSWORLD_PROVIDER", "")).strip().lower()
    if provider:
        return provider, "explicit"

    commands = provider_command_statuses()
    for candidate in ("docker", "vmware", "virtualbox"):
        if commands[candidate]["ok"]:
            return candidate, "auto"

    return None, "auto"


def provider_blockers(provider_name, commands):
    if not provider_name:
        return [
            "no supported OSWorld provider command detected; install docker, vmrun, or VBoxManage"
        ]

    blockers = []
    if provider_name == "docker" and not commands["docker"]["ok"]:
        blockers.append("docker provider requested but docker command is unavailable")
    elif provider_name == "vmware" and not commands["vmware"]["ok"]:
        blockers.append("vmware provider requested but vmrun is unavailable")
    elif provider_name == "virtualbox" and not commands["virtualbox"]["ok"]:
        blockers.append("virtualbox provider requested but VBoxManage is unavailable")
    elif provider_name not in {"docker", "vmware", "virtualbox"}:
        blockers.append(
            f"unsupported IOI_OSWORLD_PROVIDER '{provider_name}'; expected docker, vmware, or virtualbox"
        )
    return blockers


def client_password():
    return os.environ.get("IOI_OSWORLD_CLIENT_PASSWORD", "").strip()


def default_validation_task():
    return {
        "id": "94d95f96-9699-4208-98ba-3c3119edf9c2",
        "instruction": "I want to install Spotify on my current system. Could you please help me?",
        "config": [
            {
                "type": "execute",
                "parameters": {
                    "command": [
                        "python",
                        "-c",
                        "import pyautogui; import time; pyautogui.click(960, 540); time.sleep(0.5);",
                    ]
                },
            }
        ],
        "evaluator": {
            "func": "check_include_exclude",
            "result": {"type": "vm_command_line", "command": "which spotify"},
            "expected": {
                "type": "rule",
                "rules": {"include": ["spotify"], "exclude": ["not found"]},
            },
        },
    }


def sanitize_json(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {"type": "bytes", "length": len(value)}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): sanitize_json(inner) for key, inner in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [sanitize_json(inner) for inner in value]
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass
    return repr(value)


def summarize_observation(observation):
    if not isinstance(observation, dict):
        return {"type": type(observation).__name__}

    summary = {"keys": sorted(str(key) for key in observation.keys())}
    for field in ("instruction", "accessibility_tree", "terminal"):
        if field in observation:
            value = observation.get(field)
            if value is None:
                summary[f"{field}_present"] = False
            elif isinstance(value, bytes):
                summary[f"{field}_bytes"] = len(value)
            else:
                text = str(value)
                summary[f"{field}_present"] = bool(text.strip())
                summary[f"{field}_chars"] = len(text)

    if "screenshot" in observation:
        screenshot = observation.get("screenshot")
        if isinstance(screenshot, bytes):
            summary["screenshot_bytes"] = len(screenshot)
        elif screenshot is None:
            summary["screenshot_present"] = False
        else:
            summary["screenshot_present"] = True
            summary["screenshot_type"] = type(screenshot).__name__
            if isinstance(screenshot, str):
                summary["screenshot_chars"] = len(screenshot)

    return summary


def bridge_preflight():
    source_overrides = configure_source_overrides()
    python_status = python_version_status()
    requirements = {
        "desktop_env.desktop_env": {
            **import_status("desktop_env.desktop_env"),
            "discoverable": discoverable_module_status("desktop_env.desktop_env"),
        },
        "gymnasium": import_status("gymnasium"),
    }
    commands = provider_command_statuses()
    provider_name, provider_resolution = resolve_provider()
    kvm = kvm_support_status()

    blockers = []
    warnings = []

    if not python_status["ok"]:
        blockers.append("python >= 3.10 is required for OSWorld")
    desktop_env_status = requirements["desktop_env.desktop_env"]
    desktop_env_discoverable = desktop_env_status.get("discoverable", {})
    desktop_env_missing_dependency = missing_dependency_name(
        desktop_env_status.get("detail", "")
    )
    if not desktop_env_status["ok"]:
        if not desktop_env_discoverable.get("ok"):
            blockers.append("missing or unusable desktop_env package/source")
        elif (
            desktop_env_missing_dependency
            and desktop_env_missing_dependency != "desktop_env"
            and requirements["gymnasium"]["ok"] is False
            and desktop_env_missing_dependency == "gymnasium"
        ):
            warnings.append(
                "desktop_env source is discoverable, but import is currently blocked by missing transitive dependency 'gymnasium'"
            )
        elif desktop_env_missing_dependency and desktop_env_missing_dependency != "desktop_env":
            blockers.append(
                f"desktop_env import is blocked by missing transitive dependency '{desktop_env_missing_dependency}'"
            )
        else:
            blockers.append("desktop_env package/source is present but import failed")
    if not requirements["gymnasium"]["ok"]:
        blockers.append("missing gymnasium python package")
    blockers.extend(provider_blockers(provider_name, commands))

    if provider_name == "docker" and kvm["checked"] and kvm["supported"] is False:
        warnings.append("docker provider is available but host KVM support was not detected")
    if not client_password():
        warnings.append(
            "IOI_OSWORLD_CLIENT_PASSWORD is unset; some OSWorld tasks that need sudo or proxy setup may fail"
        )
    if provider_name in {"vmware", "virtualbox"} and not os.environ.get("IOI_OSWORLD_VM_PATH", "").strip():
        warnings.append(
            f"{provider_name} provider selected without IOI_OSWORLD_VM_PATH; DesktopEnv may attempt to resolve a VM automatically"
        )

    payload = {
        "benchmark": "osworld",
        "bridge": "desktop_env",
        "ok": not blockers,
        "blockers": blockers,
        "warnings": warnings,
        "python": python_status,
        "requirements": requirements,
        "provider": {
            "requested": os.environ.get("IOI_OSWORLD_PROVIDER", "").strip() or None,
            "resolved": provider_name,
            "resolution": provider_resolution,
            "commands": commands,
            "kvm": kvm,
        },
        "env": {
            "os_type": os.environ.get("IOI_OSWORLD_OS_TYPE", "Ubuntu"),
            "vm_path_provided": bool(os.environ.get("IOI_OSWORLD_VM_PATH", "").strip()),
            "client_password_present": bool(client_password()),
        },
        "source_overrides": source_overrides,
    }
    emit(payload)
    return 0 if not blockers else 2


def validation_run(args):
    configure_source_overrides()
    provider_name, provider_resolution = resolve_provider(args.provider_name)
    if not provider_name:
        raise RuntimeError(
            "could not resolve an OSWorld provider; run preflight and install docker, vmrun, or VBoxManage"
        )

    from desktop_env.desktop_env import DesktopEnv

    result_path = Path(args.result_path)
    result_path.parent.mkdir(parents=True, exist_ok=True)

    env = None
    try:
        env = DesktopEnv(
            provider_name=provider_name,
            path_to_vm=args.path_to_vm or os.environ.get("IOI_OSWORLD_VM_PATH", "").strip() or None,
            os_type=args.os_type,
            action_space=args.action_space,
            headless=args.headless,
            require_a11y_tree=False,
            require_terminal=False,
            client_password=client_password(),
        )

        task = default_validation_task()
        reset_observation = env.reset(task_config=task)
        step_observation, reward, done, info = env.step(args.action)

        payload = {
            "ok": True,
            "benchmark": "osworld",
            "bridge": "desktop_env",
            "provider_name": provider_name,
            "provider_resolution": provider_resolution,
            "os_type": args.os_type,
            "action_space": args.action_space,
            "headless": args.headless,
            "task_id": task["id"],
            "instruction": task["instruction"],
            "action": args.action,
            "reset_observation": summarize_observation(reset_observation),
            "step_observation": summarize_observation(step_observation),
            "reward": sanitize_json(reward),
            "done": sanitize_json(done),
            "info": sanitize_json(info),
            "result_path": str(result_path),
        }
        result_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        emit(payload)
        return 0
    finally:
        if env is not None:
            try:
                env.close()
            except Exception:
                pass


def build_parser():
    parser = argparse.ArgumentParser(
        description="Bridge OSWorld DesktopEnv bring-up into repo-typed preflight and validation commands."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("preflight", help="Check OSWorld DesktopEnv dependencies and provider readiness.")

    validate = subparsers.add_parser(
        "validate",
        help="Run the official quickstart-style DesktopEnv validation on the resolved provider.",
    )
    validate.add_argument("--provider-name", default=None)
    validate.add_argument("--path-to-vm", default=None)
    validate.add_argument(
        "--os-type", default=os.environ.get("IOI_OSWORLD_OS_TYPE", "Ubuntu")
    )
    validate.add_argument("--action-space", default="pyautogui")
    validate.add_argument("--action", default="pyautogui.rightClick()")
    validate.add_argument("--headless", action="store_true")
    validate.add_argument("--result-path", required=True)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "preflight":
            return bridge_preflight()
        if args.command == "validate":
            return validation_run(args)
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
