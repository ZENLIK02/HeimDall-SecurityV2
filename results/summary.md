# Heimdall Frozen Bounded-DAST Evaluation Summary

Frozen validator SHA-256: `2bbb3b1086cdfe249b50856179854a325be870ce43d312788fb3f1b063d5ef31`
Frozen external config SHA-256: `b47cceefb35bd12878adb1ee9e9474f74bde862eb37004e6dfcc2b3ff08182b3`

The full eligible set uses the natural OWASP BenchmarkJava label distribution; no sampling, balancing, or cap was applied. Two process-isolated runs produced identical verdicts and identical per-category counts.

### (a) Full eligible-set external results

| Category | N (+/−) | TP | TN | FP | FN | NR | Coverage (95% Wilson CI) | Decided accuracy (95% Wilson CI) | Counterfactual TP/TN/FP/FN | Counterfactual accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| xss/CWE-79 | 56 (39/17) | 33 | 0 | 0 | 0 | 23 | 58.93% (45.88%–70.83%) | 100.00% (89.57%–100.00%) | 33/17/0/6 | 89.29% |
| sqli/CWE-89 | 53 (31/22) | 0 | 0 | 0 | 0 | 53 | 0.00% (0.00%–6.76%) | — (—) | 0/22/0/31 | 41.51% |
| pathtraver/CWE-22 | 27 (15/12) | 0 | 0 | 0 | 0 | 27 | 0.00% (0.00%–12.46%) | — (—) | 0/12/0/15 | 44.44% |
| cmdi/CWE-78 | 28 (15/13) | 12 | 0 | 0 | 0 | 16 | 42.86% (26.51%–60.93%) | 100.00% (75.75%–100.00%) | 12/13/0/3 | 89.29% |
| **Overall** | **164 (100/64)** | **45** | **0** | **0** | **0** | **119** | **27.44% (21.19%–34.73%)** | **100.00% (92.13%–100.00%)** | **45/64/0/55** | **66.46%** |

### (b) Abstention causes

| Cause | Count | Share of NR |
|---|---:|---:|
| no authorized target | 0 | 0.00% |
| missing auth context | 0 | 0.00% |
| multi-step state | 0 | 0.00% |
| unsupported category | 0 | 0.00% |
| safety-gate rejection | 0 | 0.00% |
| no declared negative predicate | 119 | 100.00% |
| other | 0 | 0.00% |
| **Total** | **119** | **100.00%** |

### (c) Safety-gate and transport-control results

| Control set | Passed / total | Rate (95% Wilson CI) | Rejected-case sockets | Forbidden non-loopback sockets |
|---|---:|---:|---:|---:|
| Preflight rejection | 26 / 26 | 100.00% (87.13%–100.00%) | 0 | 0 |
| Transport containment controls | 3 / 3 | 100.00% (43.85%–100.00%) | N/A | 0 |
| **Overall unsafe-action prevention** | **29 / 29** | **100.00% (88.30%–100.00%)** | **0** | **0** |

Balanced-40 reproduction: TP=10, TN=0, FP=0, FN=0, NR=30, coverage=25.00%, decided accuracy=100.00%. These values match the frozen pilot exactly.

Full two-run validator wall time: 29.595114 s; requests emitted: 328; 90.229005 ms per emitted request.

Total timed evaluation scope (external parent including the balanced reproduction, plus the safety suite): 34.741592 s; requests emitted: 371; 93.643106 ms per emitted request. Benchmark-container startup is outside this timed scope.

Safety-scope note: preflight rejection cases must and did open zero sockets. The oversized-response, redirect, and one-request tests necessarily opened one initial loopback socket each; they are reported separately as transport-containment controls. No non-loopback socket was opened.
