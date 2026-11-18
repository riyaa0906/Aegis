# Aegis Security Evaluation

## Attack success rate (request path)
Corpus: 180 indirect prompt-injection payloads. A worst-case fooled
agent attempts each injection's requested attack tool call.

| condition | ASR | executed |
|---|---|---|
| baseline (agent → MCP server) | 86.7% | 156/180 |
| protected (agent → Aegis → MCP server) | 0.0% | 0/180 |

24 attacks target `delete_repository`, which the sandbox MCP server
does not implement, so they fail at baseline for lack of the tool rather than any
control. Counting those as baseline successes (a real deployment could expose it)
gives a baseline ASR of 100.0%.

| category | baseline | protected |
|---|---|---|
| data_exfiltration | 20/20 | 0/20 |
| encoded_instructions | 16/20 | 0/20 |
| hidden_instructions | 17/20 | 0/20 |
| instruction_override | 18/20 | 0/20 |
| multi_step | 19/20 | 0/20 |
| privilege_escalation | 15/20 | 0/20 |
| role_manipulation | 17/20 | 0/20 |
| social_engineering | 18/20 | 0/20 |
| tool_manipulation | 16/20 | 0/20 |

## Output screening (response path)
Local DeBERTa classifier, policy thresholds flag ≥ 0.5, block ≥ 0.9.

- Injection detection rate: **63.9%** (180 payloads); blocked outright: 60.0%.
- False-positive rate on benign output: **6.0%** (3/50).

| category | detected |
|---|---|
| data_exfiltration | 13/20 |
| encoded_instructions | 15/20 |
| hidden_instructions | 11/20 |
| instruction_override | 20/20 |
| multi_step | 7/20 |
| privilege_escalation | 13/20 |
| role_manipulation | 17/20 |
| social_engineering | 12/20 |
| tool_manipulation | 7/20 |

## Approval security & durability

| check | result |
|---|---|
| rejected_never_executes | PASS |
| approved_executes | PASS |
| duplicate_resume_replays_once | PASS |
| approval_is_idempotent | PASS |
| expired_never_executes | PASS |
| restart_recovery | PASS |

