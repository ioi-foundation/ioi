#!/usr/bin/env python3
"""Summarize nonce-correlated diagnostic events; never adjudicate authorization."""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path

EVENTS = {"operation_started", "operation_finished", "member_work_queued",
          "member_work_completed", "reply_routed"}


def summarize(directory):
    operations, sources = {}, {}
    unparsed_lines = 0
    malformed_json_lines = 0
    for path in sorted(directory.glob("*-orch.log")):
        raw = path.read_bytes()
        sources[path.name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        for line in raw.decode("utf-8", errors="replace").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                unparsed_lines += 1
                malformed_json_lines += int(line.lstrip().startswith("{"))
                continue
            if not isinstance(record, dict):
                unparsed_lines += 1
                continue
            fields = record.get("fields", {})
            if not isinstance(fields, dict) or fields.get("event") not in EVENTS:
                continue
            nonce = fields.get("nonce")
            if not isinstance(nonce, str) or not nonce:
                malformed_json_lines += 1
                continue
            event = {"node_log": path.name, "timestamp": record.get("timestamp"), **fields}
            operations.setdefault(nonce, []).append(event)
    result = {}
    for nonce, events in sorted(operations.items()):
        events.sort(key=lambda event: event.get("timestamp") or "")
        starts = [e for e in events if e["event"] == "operation_started"]
        start_time = None
        if len(starts) == 1:
            try:
                start_time = datetime.fromisoformat(starts[0]["timestamp"].replace("Z", "+00:00"))
            except (AttributeError, TypeError, ValueError):
                pass
        for event in events:
            if start_time is not None:
                try:
                    time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                    event["wall_millis_from_start_log"] = round((time - start_time).total_seconds() * 1000, 3)
                except (AttributeError, TypeError, ValueError):
                    pass
        result[nonce] = {"counts": dict(Counter(e["event"] for e in events)), "events": events}
    return {"scope": "diagnostic observations, not coverage proof or authorization",
            "timing": "wall-clock log timestamps; not the protocol monotonic deadline",
            "sources": sources, "unparsed_lines": unparsed_lines,
            "malformed_json_lines": malformed_json_lines, "operations": result}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component_directory", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    report = summarize(args.component_directory)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"source_files": len(report["sources"]),
                      "operations": len(report["operations"]),
                      "malformed_json_lines": report["malformed_json_lines"]}))
