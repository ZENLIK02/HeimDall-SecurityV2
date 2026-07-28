# Algorithm 1: Heimdall Bounded DAST Validation

## Purpose

Heimdall evaluates an existing SAST alert only when a fixed, authorized,
non-destructive runtime probe and explicit evidence predicates are available.
The evaluated path is deterministic and does not use an LLM.

## Pseudocode

```text
Algorithm 1 Heimdall Bounded DAST Validation
Input: SAST alert a, loopback allowlist L
Output: d in {Confirmed, Not Reproduced Under Test, Needs Review}

1:  if kill switch is on or bounded DAST is disabled then
2:      return Needs Review
3:  end if
4:  if a has no explicit runtime authorization mapping then
5:      return Needs Review
6:  end if
7:  if a requires authentication or multi-step state then
8:      return Needs Review
9:  end if
10: if a has no bounded positive evidence predicate then
11:     return Needs Review
12: end if
13: p <- BuildFixedProbe(a)
14: if p.method not in {GET, POST} then
15:     return Needs Review
16: end if
17: if endpoint or payload violates the safety policy then
18:     return Needs Review
19: end if
20: u <- ResolveRequestURL(p)
21: if Origin(u) is not an exact member of L or does not resolve only to loopback then
22:     return Needs Review
23: end if
24: r <- SendExactlyOneRequest(p, no redirects, bounded timeout and response)
25: if PositivePredicate(a, r) is satisfied then
26:     return Confirmed
27: end if
28: if DeclaredNegativePredicate(a, r) is satisfied then
29:     return Not Reproduced Under Test
30: end if
31: return Needs Review
```

## Decision invariant

Absence of the positive marker is not, by itself, negative evidence. A
not-reproduced verdict requires a separately declared negative marker or status
predicate. The verdict does not authorize automatic suppression of the SAST
alert.
