# Token usage and cost report

## Run

- Prediction artifact produced: **yes**
- Requests processed: **518**
- Resolved: **518**
- Unresolved: **0**

## Model usage

| Provider | Model | Calls | Cache hits | Input tokens | Output tokens | Total tokens | Estimated cost |
|---|---|---:|---:|---:|---:|---:|---:|
| local Ollama | qwen2.5:0.5b | 0 | 382 | 0 | 0 | 0 | $0.000000 |

## Overall totals

- Input tokens: **0**
- Output tokens: **0**
- Total tokens: **0**
- Average tokens per request: **0.00**
- Estimated total cost: **$0.000000**
- Estimated cost per request: **$0.00000000**
- Model elapsed time: **0.000 seconds**
- Grounded lexical fallbacks after malformed model responses: **0**
- Evidence interpretations left unresolved after malformed responses: **0**

The configured model runs locally through Ollama, so the estimated hosted inference cost is $0.00. This estimate excludes local electricity and hardware costs. If `Prediction artifact produced` is **no**, this is a diagnostic run and must not be described as the run that produced a final `output.csv`.

Cache accounting: the figures above count new model calls/tokens in this run. A warm replay can have cache hits and zero new tokens. Cached interpretations originated in earlier local-model runs; their original token counts are not stored per cache entry and are not included in these final-run totals. Clear the local cache for a cold run; no cache or model weights are included in the source archive.
