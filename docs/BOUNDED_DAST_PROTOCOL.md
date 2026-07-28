# Heimdall Bounded DAST Protocol

Protocol identifier: `heimdall-bounded-dast/1.0`

## Purpose

The protocol collects narrowly scoped runtime evidence for an existing SAST
alert. It is not a crawler, endpoint-discovery engine, payload mutator, or
general-purpose DAST scanner.

## Execution contract

An alert is executable only when all of the following are true:

1. Active validation is enabled and the kill switch is off.
2. The alert carries an explicit local runtime authorization mapping.
3. The request method is GET or POST.
4. The endpoint is relative and contains no credentials, fragment, control
   characters, or path traversal.
5. The final request origin exactly matches a configured loopback allowlist
   entry and resolves only to loopback addresses.
6. The serialized payload is at most 8 KiB and contains no blocked destructive
   fragment or non-loopback network destination.
7. A bounded positive evidence marker is declared.

Exactly one request is sent for an executable alert. Redirects are not followed,
the timeout is bounded, and the captured response body is size-limited.

## Decision contract

- `Confirmed`: the declared positive evidence marker is observed in the
  category-specific channel, and the status code matches when one was declared.
- `Not Reproduced Under Test`: a separately declared negative evidence marker
  or negative status predicate is observed.
- `Needs Review`: neither predicate is satisfied, the target cannot be reached,
  context is missing, or any safety precondition fails.

Marker absence by itself is not negative evidence. `Not Reproduced Under Test`
does not prove that the SAST alert is a false positive and must not trigger
automatic suppression.

## Audit data

Each result records the protocol version, redacted request URL, method, request
count, response status, marker outcomes, truncation state, response SHA-256,
and whether a redirect was followed. Response bodies are not copied into the
audit report.

## Running

Start the included loopback lab, generate the controlled alert manifest, and
run:

```bash
python -m heimdall.cli bounded-dast \
  --dataset test_data/heimdall_active_local_alerts.jsonl \
  --config heimdall.yml \
  --output reports/bounded_dast
```
