# Token usage and cost report

## Run

- Prediction artifact produced: **no**
- Requests processed: **518**
- Resolved: **200**
- Unresolved: **318**

## Model usage

| Provider | Model | Calls | Cache hits | Input tokens | Output tokens | Total tokens | Estimated cost |
|---|---|---:|---:|---:|---:|---:|---:|
| local Ollama | qwen2.5:0.5b | 4 | 387 | 3268 | 1080 | 4348 | $0.000000 |

## Overall totals

- Input tokens: **3268**
- Output tokens: **1080**
- Total tokens: **4348**
- Average tokens per request: **8.39**
- Estimated total cost: **$0.000000**
- Estimated cost per request: **$0.00000000**
- Model elapsed time: **38.947 seconds**
- Grounded lexical fallbacks after malformed model responses: **0**
- Evidence interpretations left unresolved after malformed responses: **2**

The configured model runs locally through Ollama, so the estimated hosted inference cost is $0.00. This estimate excludes local electricity and hardware costs. If `Prediction artifact produced` is **no**, this is a diagnostic run and must not be described as the run that produced a final `output.csv`.
