# GPT-4.1-mini Ablation Plan

Default runs do not call external APIs. To run an authorized ablation, set:

```bash
export HEIMDALL_ENABLE_REAL_LLM=1
export OPENAI_API_KEY=...
export HEIMDALL_LLM_MODEL=gpt-4.1-mini
```

Record model, timestamp, prompt template hash, temperature, number of runs, latency, token usage, approximate cost, and output variance. The LLM may suggest validation hypotheses only; localhost evidence and the decision engine must still make the final decision.
