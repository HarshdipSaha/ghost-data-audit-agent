# Evaluation report

## Method

The predictor receives only the request, identity/activity tables, rules and evidence. The evaluator reads `sample_output.csv` after prediction and compares it independently. Team-authored adversarial fixtures live in `code/tests/test_core.py`; their results are reported separately from held-out sample scores.

Command: `python code/evaluation/main.py artifacts\sample_resolved_diagnostic.csv dataset\sample_output.csv --allow-missing --run-summary artifacts\full_run_summary.json`

## Sample results

| Metric | Result |
|---|---:|
| Cases | 32 |
| Resolved prediction coverage | 87.500% (28/32) |
| Status accuracy | 87.500% (28/32) |
| Exact sequence accuracy | 18.750% (6/32) |
| Step accuracy | 56.995% |
| Field accuracy | 68.818% (949/1379) |
| Resource recall | 66.667% (74/111) |

When coverage is below 100%, this is diagnostic evaluation. Missing cases count as incorrect for status and exact sequence accuracy; their expected steps and resources remain in the denominators. No status was invented for an unresolved request. Status accuracy restricted to resolved cases: 100.000%. Missing case IDs: ['case_01', 'case_02', 'case_04', 'case_06'].

## Team-authored evaluation cases

1. Evidence bundle captured after audit cutoff contains an older embedded fact: future artifact availability is excluded.
2. Primary database is empty while a physical read replica retains a subject row: replica remains a violation.
3. An identity's email changes after the audit cutoff: later email ownership does not leak backward.
4. A same-trace cache miss is followed by an explicit 404 profile read: only the 404 read supports absence.
5. An escaped log envelope preserves trace and service boundaries while a neighboring trace is ignored.
6. A correction request says "without removing any of my records": deletion authorization is false, including when the local model votes true.
7. A catalog-linked customer statement and an object metadata panel prove concrete copies exist without relying on filenames as case labels.
8. A restore-candidate read joins its own trace identity and interprets eligibility plus deletion-block controls; retries alone establish no state.
9. Missing policy metadata cannot justify destroying present security records or conversation history; explicit expiry/private predicates remain effective.
10. A retained record's stable reference establishes why a deleted-account tombstone must remain with direct identifiers removed.

## Failures and improvements

1. Multi-request local-model batches sometimes attached a valid quote to a neighboring request. Authorization now uses one request per model prompt, exact-source quote checks and a three-way unresolved state for unsupported intent.
2. Resource or catalog mentions could be mistaken for live record reads. Document evidence now requires a visible row or state, keeps embedded fact time separate from capture availability, and rejects mentions that postdate the audit cutoff.
3. Email or phone aliases could be recycled to another stable user. Identity discovery now checks cutoff ownership and rejects conflicting stable-user references.
4. A clean primary table could hide a populated physical replica, and one citation could accidentally stand in for multiple copies. Replica scopes remain separate, and complete decisions retain evidence for each physical obligation.
5. A destructive fallback treated missing retention/context metadata as permission to delete security logs and conversations. Present security records now remain until supplied evidence establishes expiry; conversations are redacted unless explicitly private/nonshared. Backup access controls are blocked while the archive remains available. These are documented policy conventions; they do not create missing identity/resource links.
6. Restore-candidate evaluations were omitted by the event adapter. They now preserve trace identity and distinguish eligible, unblocked recovery paths from blocked ones. Replica service labels are mapped to the owning logical system while physical scope is retained.

## Remaining limitations

Four sample requests remain unresolved: three have no independently grounded resource association, and one lacks an authoritative state read for a discovered account. Some clean profile/analytics evidence has no subject or lookup key, so it cannot be attributed merely by reading the sample answer. Remaining sequence mismatches include missing resource relationships, policy interpretations, citation choices, and additional backup-presence checks. Exact sequence accuracy remains substantially below status accuracy; resolving all full-set rows does not establish their hidden-label accuracy.

The current official contract was checked against the [organizer problem statement](https://github.com/interviewstreet/hackerrank-orchestrate-october26/blob/main/problem_statement.md). It requires audit-time, participant-facing evidence; no organizer truth or reference-answer mapping is used by the predictor.

This report reflects the current run. Regenerate it after every prediction change. Any mismatch should be traced to a general parser, time, identity, coverage, policy, citation or ordering defect; no per-case prediction lookup is permitted.

## Full request run

Requests: **518**; resolved: **518**; unresolved: **0**; complete output written: **yes**.
The full set has no participant-visible reference labels, so full-set correctness is not measured.
