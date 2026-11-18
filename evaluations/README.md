# Aegis Security Evaluation

Measures whether Aegis actually improves security, by comparing two systems on the same
corpus of indirect prompt-injection attacks:

- **Baseline** — agent → MCP server → tool. No gateway.
- **Protected** — agent → Aegis → MCP server → Aegis → agent.

## What is measured, and why there is no LLM in the loop

Aegis's thesis is that the _system_ stops the attack even when the model is fooled, not that
the model is never fooled. Measuring "how often is the model fooled" would measure the model,
not Aegis. So the agent is modelled at its **worst case**: it is assumed to be fully
manipulated and to attempt exactly the tool call each injection asked for. The question the
eval answers is then the one that matters — _when the agent is fooled, does the dangerous
action actually happen?_ This is deterministic and reproducible; nothing depends on a model's
sampling or on an API key.

Two independent Aegis defences are measured separately:

| defence                                      | path     | metric                                                                  |
| -------------------------------------------- | -------- | ----------------------------------------------------------------------- |
| authorization + effect class + approval gate | request  | **attack success rate**, baseline vs protected                          |
| DeBERTa output screener + policy thresholds  | response | **detection rate** on attacks, **false-positive rate** on benign output |

The request-path measurement is fully faithful: it issues the real attack tool call against
the real MCP server (baseline) and through the real gateway (protected), and records whether
it executed. The response-path measurement calls the real classifier service on each payload
and applies the same thresholds the gateway reads from `policies/development.yaml`.

Approval security and durability are exercised as live probes against the running gateway:
rejected/expired approvals must never execute, an approved request executes exactly once, a
duplicate approval is idempotent, and an approval survives a full gateway restart.

## Corpus

- `injections/` — 180 payloads, 9 categories × 20 (`instruction_override`, `role_manipulation`,
  `data_exfiltration`, `tool_manipulation`, `privilege_escalation`, `hidden_instructions`,
  `encoded_instructions`, `multi_step`, `social_engineering`). Each row carries the poisoned
  tool output (`payload`) and the concrete attack it is trying to cause (`attack.tool`,
  `attack.arguments`) — always an exfiltration or destructive call to `attacker@evil.example`
  or a protected repository.
- `benign/benign.jsonl` — 50 realistic tool outputs (bug reports, payment lookups, issue
  receipts) that must **not** be flagged.

## Running

```bash
pnpm build
pnpm classifier:install     # first time only; downloads the model
docker compose up -d postgres redis
bash evaluations/run.sh
```

The script brings up the classifier, MCP server and gateway, runs every measurement,
restarts the gateway mid-run to prove durable approval recovery, tears everything down, and
writes raw per-item results plus a summary to `results/`.

## Results

`results/` holds the raw output of the most recent run — one JSON file per measurement, each
with a `generated_at` timestamp and every per-item score/decision — and `summary.md`, the
rendered report. Regenerate the report from existing raw results without re-running the
measurements with `uv run --directory apps/agent python evaluations/summarize.py`.

All numbers in `summary.md` come from an actual run. None are hand-written.
