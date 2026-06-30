# Algorithm 1: Heimdall Closed-Loop Validation

## Purpose

Heimdall converts a static security alert into a safe validation hypothesis, evaluates the hypothesis in a dry-run or allowlisted DAST environment, and returns one of three decisions: True Positive, False Positive, or Needs Review.

## Pseudocode

```text
Algorithm 1 Heimdall Closed-Loop Validation
Input: SAST alert a
Output: decision d in {True Positive, False Positive, Needs Review}

1:  c <- ExtractContext(a)
2:  g <- PromptGuard(c)
3:  if g is rejected then
4:      return Needs Review with prompt-safety explanation
5:  end if

6:  h <- GenerateExploitabilityHypothesis(g)
7:  y <- ValidateStructuredLLMOutput(h)
8:  if y.confidence is low or y.recommended_action = needs_review then
9:      return Needs Review with uncertainty explanation
10: end if

11: p <- GenerateSafePayload(y, c)
12: s <- ValidatePayloadSafety(p)
13: if s is blocked then
14:     return Needs Review with safety-policy explanation
15: end if

16: r <- ExecuteDAST(p, target allowlist, dry-run default)
17: e <- AnalyzeResponse(r, p.expected_evidence)

18: if e.status = confirmed then
19:     d <- True Positive
20: else if e.status = not_confirmed and y.exploitability = unlikely_exploitable then
21:     d <- False Positive
22: else if e.status = not_confirmed then
23:     d <- False Positive
24: else
25:     d <- Needs Review
26: end if

27: return d with evidence, explanation, safety notes, and recommended action
```

## Notes

- Dynamic validation is dry-run by default.
- Production targets are blocked unless explicitly configured.
- Destructive payload patterns are rejected before execution.
- Business logic and authenticated workflows are conservatively classified as Needs Review when required context is unavailable.
