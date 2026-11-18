"""Renders the raw evaluation result files into a concise report.

Reads only what previous runs wrote to evaluations/results/; computes nothing itself, so
every number here traces back to a recorded measurement.
"""

from __future__ import annotations

import json
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"


def load(name: str) -> dict | None:
    path = RESULTS / name
    return json.loads(path.read_text()) if path.exists() else None


def pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def main() -> None:
    lines = ["# Aegis Security Evaluation", ""]

    asr = load("asr.json")
    if asr:
        lines += [
            "## Attack success rate (request path)",
            f"Corpus: {asr['total']} indirect prompt-injection payloads. A worst-case fooled",
            "agent attempts each injection's requested attack tool call.",
            "",
            "| condition | ASR | executed |",
            "|---|---|---|",
            (
                f"| baseline (agent → MCP server) | {pct(asr['baseline_asr'])} | "
                f"{asr['baseline_executions']}/{asr['total']} |"
            ),
            (
                f"| protected (agent → Aegis → MCP server) | {pct(asr['protected_asr'])} | "
                f"{asr['protected_executions']}/{asr['total']} |"
            ),
            "",
            (
                f"{asr['delete_repository_attacks']} attacks target `delete_repository`, which "
                "the sandbox MCP server"
            ),
            "does not implement, so they fail at baseline for lack of the tool rather than any",
            "control. Counting those as baseline successes (a real deployment could expose it)",
            f"gives a baseline ASR of {pct(asr['baseline_asr_with_denied_tool_available'])}.",
            "",
            "| category | baseline | protected |",
            "|---|---|---|",
        ]
        for cat, b in sorted(asr["by_category"].items()):
            lines.append(
                f"| {cat} | {b['baseline']}/{b['total']} | {b['protected']}/{b['total']} |"
            )
        lines.append("")

    screening = load("screening.json")
    if screening:
        t = screening["thresholds"]
        lines += [
            "## Output screening (response path)",
            f"Local DeBERTa classifier, policy thresholds flag ≥ {t['flag']}, block ≥ {t['block']}.",
            "",
            (
                f"- Injection detection rate: **{pct(screening['injection_detection_rate'])}** "
                f"({screening['injection_total']} payloads); "
                f"blocked outright: {pct(screening['injection_block_rate'])}."
            ),
            (
                f"- False-positive rate on benign output: "
                f"**{pct(screening['false_positive_rate'])}** "
                f"({screening['false_positives']}/{screening['benign_total']})."
            ),
            "",
            "| category | detected |",
            "|---|---|",
        ]
        for cat, b in sorted(screening["by_category"].items()):
            lines.append(f"| {cat} | {b['detected']}/{b['total']} |")
        lines.append("")

    approval = load("approval.json")
    timeout = load("timeout.json")
    durability = load("durability.json")
    if approval or timeout or durability:
        lines += ["## Approval security & durability", "", "| check | result |", "|---|---|"]
        for check in (approval or {}).get("checks", []):
            lines.append(f"| {check['check']} | {'PASS' if check['passed'] else 'FAIL'} |")
        for single in (timeout, durability):
            if single:
                lines.append(f"| {single['check']} | {'PASS' if single['passed'] else 'FAIL'} |")
        lines.append("")

    report = "\n".join(lines)
    (RESULTS / "summary.md").write_text(report + "\n")
    print(report)


if __name__ == "__main__":
    main()
