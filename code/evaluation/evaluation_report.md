# Evaluation report

## Method and run status

The predictor receives only participant-facing request, identity/activity, policy, and evidence files. The sample reference is read only by the independent evaluator after a complete prediction CSV exists.

- Requests: **518**
- Audits resolved: **200**
- Audits unresolved: **318**
- Complete prediction CSV produced: **no**
- Sample request diagnostic: **11/32 resolved, 21 unresolved**; score not measured.


No complete prediction CSV was produced, so comparison with `sample_output.csv` was not run. The following metrics are **not measured**; they are not zero scores.

## Sample metrics

| Metric | Result |
|---|---:|
| Case-level deletion-status accuracy | Not measured |
| Exact sequence accuracy | Not measured |
| Step accuracy | Not measured |
| Field accuracy | Not measured |
| Resource recall | Not measured |

## Additional team-authored evaluation cases

1. `test_rejects_nonlocal_or_noncanonical_model_endpoints`: attacker-controlled hostnames, userinfo, non-HTTP schemes, paths, and queries are rejected.
2. `test_non_boolean_direct_identifier_values_do_not_establish_attribution`: false/null-like values cannot create a false anonymization obligation.
3. `test_false_policy_predicates_are_distinct_from_missing_proof`: explicitly disproven shared-context predicates differ from missing policy evidence.
4. `test_document_mention_is_not_state_and_future_embedded_time_is_excluded`: later or merely mentioned resources do not become audit-time state reads.
5. `test_complete_cites_each_physical_copy`: a replica requires its own evidence citation.

## Unresolved diagnostic reasons

Counts below are issue occurrences; one request can have multiple unresolved resources.

| Reason | Count |
|---|---:|
| SECURITY_AUDIT_LOG: Policy obligation unresolved | 330 |
| SUPPORT_MESSAGE: Policy obligation unresolved | 151 |
| SUPPORT_ATTACHMENT: Policy obligation unresolved | 21 |
| ACCOUNT_TOMBSTONE: Policy obligation unresolved | 16 |
| No timely authoritative state read | 4 |
| ANALYTICS_PROFILE: Policy obligation unresolved | 1 |
| LEGAL_HOLD_RECORD: Policy obligation unresolved | 1 |
| No grounded resources discovered | 1 |

## Failures and improvements

The full run left 318 requests unresolved because supplied policy predicates or timely state observations were not established. The largest issue groups are shown above; missing retention intervals, ownership/context facts, or authoritative reads are kept unresolved instead of being converted into guessed statuses or remediation. Hardening added exact loopback endpoint parsing, disabled environment proxies and redirects, separated disproven policy conditions from missing evidence, enforced the 518-row contract, and required both evaluation reports before packaging. The parser, identity resolver, temporal gates, conditional-policy engine, local-only model transport, and output contract are covered by automated tests; passing those tests does not replace a sample score.

Regenerate this report from the latest full-run summary after every implementation change. If unresolved audits remain, report metrics as not measured and do not package a misleading `output.csv`.
