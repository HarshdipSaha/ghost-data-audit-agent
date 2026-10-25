# Artifact verification

The final complete run resolved 518/518 requests and wrote a contract-valid, sorted CSV. An independent check matched every case ID, rejected duplicates, validated every operation/state pair and consecutive step, and checked each citation against its request cutoff. Distribution: 356 INCOMPLETE, 152 COMPLETE, 10 NOT_APPLICABLE. This is artifact/coverage verification; hidden-label accuracy is unknown.

Unit and adversarial verification: **99 tests and 40 subtests passed** using `python -m pytest code/tests -q`.

The source ZIP passed CRC and exclusion checks. It was extracted into a new isolated folder with no semantic cache, then the extracted `main.py` processed the first eight requests using the supplied corpus and local Ollama. **8/8 resolved**, zero unresolved audits, and no partial submission file was emitted. Actual smoke-run inference: 13 calls, 5,771 input tokens, 1,078 output tokens (6,849 total), zero cache hits, 45.442 seconds of model elapsed time, and $0 hosted inference cost. One unproductive semantic interpretation remained unused; the audit decisions were grounded through the available deterministic evidence paths.

The smoke test verifies that the extracted program runs without the development cache. It is not a fresh-cache full-set run or a measurement against hidden answers. The final full-dataset usage report separately records its 382-hit warm replay, with no new inference tokens.

Submission predictions, source ZIP and transcript are local deliverables. The public source repository excludes the competition corpus, prediction CSVs, model/cache files, credentials and transcript.
