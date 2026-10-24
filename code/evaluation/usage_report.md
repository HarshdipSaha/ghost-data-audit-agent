# Token usage and cost report

## Run

- Prediction artifact produced: **no**
- Requests processed: **518**
- Resolved: **514**
- Unresolved: **4**

## Model usage

| Provider | Model | Calls | Cache hits | Input tokens | Output tokens | Total tokens | Estimated cost |
|---|---|---:|---:|---:|---:|---:|---:|
| local Ollama | qwen2.5:0.5b | 2 | 386 | 1546 | 540 | 2086 | $0.000000 |

## Overall totals

- Input tokens: **1546**
- Output tokens: **540**
- Total tokens: **2086**
- Average tokens per request: **4.03**
- Estimated total cost: **$0.000000**
- Estimated cost per request: **$0.00000000**
- Model elapsed time: **19.534 seconds**
- Grounded lexical fallbacks after malformed model responses: **0**
- Evidence interpretations left unresolved after malformed responses: **1**

The configured model runs locally through Ollama, so the estimated hosted inference cost is $0.00. This estimate excludes local electricity and hardware costs. If `Prediction artifact produced` is **no**, this is a diagnostic run and must not be described as the run that produced a final `output.csv`.
