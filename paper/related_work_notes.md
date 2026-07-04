# Related Work Notes

## 1. Static analysis and false positives
- Chess and McGraw discuss static analysis for security and the role of tooling in finding defects before runtime.
- Livshits and Lam show static analysis applied to finding Java application vulnerabilities.

## 2. Dynamic testing and runtime validation
- Doupé, Cova, and Vigna evaluate black-box web vulnerability scanners, providing context for runtime validation limits.

## 3. Hybrid SAST/DAST workflows
- Use search query: `hybrid static dynamic analysis vulnerability validation web applications empirical` to expand the final literature review.

## 4. LLM-assisted vulnerability reasoning
- Pearce et al. evaluate security implications of AI code generation; this motivates caution when using LLMs for security tooling.
- Use search query: `large language models vulnerability detection repair survey software security` for newer benchmark papers before submission.

## 5. Safety risks of LLM security tools
- Greshake et al. study indirect prompt injection against LLM-integrated applications; Heimdall separates LLM hypotheses from evidence-based decisions.

## 6. DevSecOps and CI/CD security
- Use search query: `DevSecOps empirical study CI/CD security SAST DAST` to add recent empirical DevSecOps references.

## 7. Human-in-the-loop triage
- Heimdall treats Needs Review as a first-class outcome for cases requiring authentication, workflow state, or human judgment.

## 8. Software supply-chain security
- Ohm et al. review open-source software supply-chain attacks, motivating CI/CD safety controls and cautious dependency handling.
