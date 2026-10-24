# Evaluation report

## Method and run status

The predictor receives only participant-facing request, identity/activity, policy, and evidence files. The sample reference is read only by the independent evaluator after a complete prediction CSV exists.

- Requests: **518**
- Audits resolved: **514**
- Audits unresolved: **4**
- Complete prediction CSV produced: **no**
- Sample request diagnostic: **25/32 resolved, 7 unresolved**; score not measured.


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

1. `test_rejects_nonlocal_or_noncanonical_model_endpoints`: attacker-controlled hosts, userinfo, non-HTTP schemes, paths, and queries are rejected.
2. `test_korean_explicit_account_deletion_and_negation`: explicit Korean deletion intent is recognized while negation and a request for instructions are not treated as authorization.
3. `test_false_policy_predicates_fall_back_to_deletion`: conditional retention exceptions do not silently suppress the underlying deletion request.
4. `test_non_boolean_direct_identifier_values_do_not_establish_attribution`: false/null-like analytics flags cannot create a false anonymization obligation.
5. `test_current_archive_inventory_row_establishes_presence`: a current, resource-grounded archive inventory row supports presence without inventing restore capability.
6. `test_complete_cites_each_physical_copy`: a replica requires its own evidence citation.

## Unresolved diagnostic reasons

Counts below are issue occurrences; one request can have multiple unresolved resources.

| Reason | Count |
|---|---:|
| No timely authoritative state read | 3 |
| No grounded resources discovered | 1 |

## Failures and improvements

The full run left 4 requests unresolved because timely state or grounded resource evidence was missing. The largest issue groups are shown above; catalog links without a current record read and ambiguous identity ownership remain unresolved rather than being converted into guessed states. Conditional retention rules now override baseline deletion only when their predicates are supported by evidence; shared attachments are redacted when exclusive ownership is not established. Hardening added exact loopback endpoint parsing, disabled environment proxies and redirects, multilingual intent checks, enforced the 518-row contract, and required both evaluation reports before packaging. The parser, identity resolver, temporal gates, conditional-policy engine, local-only model transport, and output contract are covered by automated tests; passing those tests does not replace a sample score.

Regenerate this report from the latest full-run summary after every implementation change. If unresolved audits remain, report metrics as not measured and do not package a misleading `output.csv`.
