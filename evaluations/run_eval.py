"""Aegis security evaluation.

Measures Aegis's security impact against a corpus of indirect prompt-injection payloads
and a benign set. No LLM is involved: the project's thesis is that the *system* stops the
attack even when the model is fooled, so the agent is modelled at its worst -- it attempts
exactly the tool call the injection asked for -- and we measure whether that call actually
executes with Aegis versus without it.

Two independent Aegis defences are measured:

  request path  -- authorization, effect classification and the approval gate. Baseline
                   sends the attack tool call straight to the MCP server; protected sends
                   the same call through the gateway. ASR = fraction that execute.
  response path -- the output screener. Each payload is scored by the real classifier and
                   the policy thresholds decide flag/block. Detection rate on attacks,
                   false-positive rate on benign output.

Everything reported comes from an actual run; raw per-item results are written to
evaluations/results/ so the summary is reproducible. Numbers are never hard-coded.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
POLICY = ROOT.parent / "policies" / "development.yaml"

MCP_URL = "http://127.0.0.1:3301/mcp"
GATEWAY_URL = "http://127.0.0.1:3300/mcp"
GATEWAY_APPROVALS = "http://127.0.0.1:3300/approvals"
CLASSIFIER_URL = "http://127.0.0.1:3100/classify"
ROLE = "support_agent"
AGENT_ID = "eval-agent"


# --- corpus ------------------------------------------------------------------------------


def load_injections() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted((ROOT / "injections").glob("*.jsonl")):
        rows.extend(json.loads(line) for line in path.read_text().splitlines() if line.strip())
    return rows


def load_benign() -> list[dict[str, Any]]:
    path = ROOT / "benign" / "benign.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def screening_thresholds() -> dict[str, float]:
    """Reads the same thresholds the gateway applies (mirrors screening.ts)."""
    flag, block = 0.5, 0.9
    section = False
    for raw in POLICY.read_text().splitlines():
        line = raw.strip()
        if line.startswith("output_screening:"):
            section = True
            continue
        if section and line.startswith("flag_threshold:"):
            flag = float(line.split(":", 1)[1])
        elif section and line.startswith("block_threshold:"):
            block = float(line.split(":", 1)[1])
        elif section and line and not raw.startswith(" "):
            break
    return {"flag": flag, "block": block}


# --- transports --------------------------------------------------------------------------


def classify(text: str) -> float:
    body = json.dumps({"text": text}).encode()
    request = urllib.request.Request(
        CLASSIFIER_URL, body, {"content-type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=900) as response:
        return float(json.load(response)["score"])


async def _call(url: str, headers: dict[str, str], tool: str, arguments: dict[str, Any]) -> Any:
    async with (
        create_mcp_http_client(headers=headers) as http_client,
        streamable_http_client(url, http_client=http_client) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        return await session.call_tool(tool, arguments)


def call_direct(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Baseline: straight to the MCP server, no gateway in the path."""
    result = asyncio.run(_call(MCP_URL, {}, tool, arguments))
    return {"executed": not result.is_error, "detail": _text(result)}


def call_gateway(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Protected: through Aegis, as the least-privileged support role."""
    headers = {"x-aegis-agent-id": AGENT_ID, "x-aegis-role": ROLE}
    result = asyncio.run(_call(GATEWAY_URL, headers, tool, arguments))
    meta = result.meta or {}
    return {
        "executed": not result.is_error,
        "error_code": meta.get("aegis/error_code"),
        "detail": _text(result),
    }


def _text(result: Any) -> str:
    return "\n".join(b.text for b in result.content if getattr(b, "type", "") == "text")


def http_post(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload).encode()
    request = urllib.request.Request(
        url, body, {"content-type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        return {"error": error.code}


def list_pending() -> list[dict[str, Any]]:
    with urllib.request.urlopen(GATEWAY_APPROVALS, timeout=30) as response:
        return json.load(response)["approvals"]


# --- attack success rate -----------------------------------------------------------------


def measure_asr() -> dict[str, Any]:
    """A worst-case fooled agent attempts each injection's requested attack tool call."""
    per_item = []
    for row in load_injections():
        attack = row["attack"]
        tool, args = attack["tool"], dict(attack["arguments"])
        # Unique write args per item so sandbox idempotency never merges two attacks.
        if "subject" in args:
            args["subject"] = f"{args['subject']} [{row['id']}]"
        if "title" in args:
            args["title"] = f"{args['title']} [{row['id']}]"

        baseline = call_direct(tool, args)
        protected = call_gateway(tool, args)
        per_item.append(
            {
                "id": row["id"],
                "category": row["category"],
                "attack_tool": tool,
                "baseline_executed": baseline["executed"],
                "protected_executed": protected["executed"],
                "protected_error_code": protected.get("error_code"),
            }
        )

    total = len(per_item)
    baseline_hits = sum(1 for r in per_item if r["baseline_executed"])
    protected_hits = sum(1 for r in per_item if r["protected_executed"])
    # delete_repository is not implemented on the sandbox MCP server, so those attacks fail
    # at baseline for lack of the tool rather than any control. Report both numbers.
    denied_tool = [r for r in per_item if r["attack_tool"] == "delete_repository"]
    baseline_realistic = baseline_hits + len(denied_tool)

    by_category: dict[str, dict[str, int]] = {}
    for r in per_item:
        bucket = by_category.setdefault(r["category"], {"total": 0, "baseline": 0, "protected": 0})
        bucket["total"] += 1
        bucket["baseline"] += int(r["baseline_executed"])
        bucket["protected"] += int(r["protected_executed"])

    return {
        "total": total,
        "baseline_asr": baseline_hits / total,
        "baseline_asr_with_denied_tool_available": baseline_realistic / total,
        "protected_asr": protected_hits / total,
        "baseline_executions": baseline_hits,
        "protected_executions": protected_hits,
        "delete_repository_attacks": len(denied_tool),
        "by_category": by_category,
        "items": per_item,
    }


# --- output screening: detection + false positives ---------------------------------------


def _decision(score: float, thresholds: dict[str, float]) -> str:
    if score >= thresholds["block"]:
        return "block"
    if score >= thresholds["flag"]:
        return "flag"
    return "allow"


def measure_screening() -> dict[str, Any]:
    thresholds = screening_thresholds()

    injections = []
    for row in load_injections():
        score = classify(row["payload"])
        injections.append(
            {
                "id": row["id"],
                "category": row["category"],
                "score": score,
                "decision": _decision(score, thresholds),
            }
        )
    detected = sum(1 for r in injections if r["decision"] != "allow")
    blocked = sum(1 for r in injections if r["decision"] == "block")

    benign = []
    for row in load_benign():
        score = classify(row["content"])
        benign.append(
            {"id": row["id"], "score": score, "decision": _decision(score, thresholds)}
        )
    false_positives = sum(1 for r in benign if r["decision"] != "allow")

    by_category: dict[str, dict[str, int]] = {}
    for r in injections:
        bucket = by_category.setdefault(r["category"], {"total": 0, "detected": 0})
        bucket["total"] += 1
        bucket["detected"] += int(r["decision"] != "allow")

    return {
        "thresholds": thresholds,
        "injection_total": len(injections),
        "injection_detection_rate": detected / len(injections),
        "injection_block_rate": blocked / len(injections),
        "benign_total": len(benign),
        "false_positive_rate": false_positives / len(benign),
        "false_positives": false_positives,
        "by_category": by_category,
        "injection_items": injections,
        "benign_items": benign,
    }


# --- approval security + durability ------------------------------------------------------


def _create_pending(tag: str) -> dict[str, Any]:
    call_gateway(
        "github_create_issue",
        {"repo": "acme/web", "title": f"eval {tag}", "body": f"eval probe {tag}"},
    )
    pending = [p for p in list_pending() if p["tool"] == "github_create_issue"]
    return next(p for p in pending if f"eval {tag}" in p["arguments"]["title"])


def _resume(tag: str) -> dict[str, Any]:
    return call_gateway(
        "github_create_issue",
        {"repo": "acme/web", "title": f"eval {tag}", "body": f"eval probe {tag}"},
    )


def measure_approval_security() -> dict[str, Any]:
    checks = []

    # A rejected approval must never execute the tool.
    tag = f"reject-{int(time.time())}"
    record = _create_pending(tag)
    http_post(f"{GATEWAY_APPROVALS}/{record['request_id']}/reject", {"decided_by": "ops@eval"})
    after_reject = _resume(tag)
    checks.append(
        {
            "check": "rejected_never_executes",
            "passed": not after_reject["executed"]
            and after_reject["error_code"] == "APPROVAL_REJECTED",
        }
    )

    # An approved request executes exactly once; a duplicate resume replays, not re-runs.
    tag = f"approve-{int(time.time())}"
    record = _create_pending(tag)
    http_post(f"{GATEWAY_APPROVALS}/{record['request_id']}/approve", {"decided_by": "ops@eval"})
    first = _resume(tag)
    second = _resume(tag)
    checks.append({"check": "approved_executes", "passed": first["executed"]})
    checks.append(
        {
            "check": "duplicate_resume_replays_once",
            "passed": second["executed"] and second["detail"] == first["detail"],
        }
    )

    # A duplicate approval is idempotent: approving twice leaves one decision.
    tag = f"idem-{int(time.time())}"
    record = _create_pending(tag)
    a = http_post(f"{GATEWAY_APPROVALS}/{record['request_id']}/approve", {"decided_by": "ops@eval"})
    b = http_post(
        f"{GATEWAY_APPROVALS}/{record['request_id']}/approve", {"decided_by": "someone@else"}
    )
    checks.append(
        {
            "check": "approval_is_idempotent",
            "passed": a["approval"]["decided_by"] == b["approval"]["decided_by"] == "ops@eval",
        }
    )

    return {"checks": checks, "passed": sum(c["passed"] for c in checks), "total": len(checks)}


def measure_timeout() -> dict[str, Any]:
    """Runs against a gateway started with a sub-second approval timeout."""
    tag = f"timeout-{int(time.time())}"
    _create_pending(tag)
    time.sleep(2.5)
    after = _resume(tag)
    return {
        "check": "expired_never_executes",
        "passed": not after["executed"] and after["error_code"] == "APPROVAL_TIMEOUT",
    }


def durability_before() -> None:
    """Creates and approves a request, to be resumed by a freshly restarted gateway."""
    tag = "restart-eval"
    record = _create_pending(tag)
    http_post(f"{GATEWAY_APPROVALS}/{record['request_id']}/approve", {"decided_by": "ops@eval"})
    print(record["request_id"])


def durability_after() -> dict[str, Any]:
    """After a gateway restart, the approved request must resume and execute once."""
    after = _resume("restart-eval")
    return {
        "check": "restart_recovery",
        "passed": after["executed"],
        "detail": after["detail"][:80],
    }


# --- entry -------------------------------------------------------------------------------


def _write(name: str, data: dict[str, Any]) -> None:
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / name).write_text(json.dumps(data, indent=2) + "\n")


def main() -> None:
    mode = sys.argv[1]
    stamp = datetime.now(UTC).isoformat()
    if mode == "asr":
        _write("asr.json", {"generated_at": stamp, **measure_asr()})
    elif mode == "screening":
        _write("screening.json", {"generated_at": stamp, **measure_screening()})
    elif mode == "approval":
        _write("approval.json", {"generated_at": stamp, **measure_approval_security()})
    elif mode == "timeout":
        _write("timeout.json", {"generated_at": stamp, **measure_timeout()})
    elif mode == "durability-before":
        durability_before()
    elif mode == "durability-after":
        _write("durability.json", {"generated_at": stamp, **durability_after()})
    else:
        raise SystemExit(f"unknown mode {mode}")


if __name__ == "__main__":
    main()
