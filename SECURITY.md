# Security Policy

Heimdall is safety-first. The default configuration uses dry-run validation, mock LLM behavior, local allowlisted targets, request logging, and conservative `Needs Review` decisions when context is missing.

## Safe Testing Rules

- Do not test against production systems unless you own them and have explicit authorization.
- Do not share real secrets, private source code, production URLs, or customer data in public issues.
- Keep `security.dry_run: true` unless you are testing a local or explicitly allowlisted target.
- Review `heimdall.yml` before enabling active DAST-style validation.
- Use the local vulnerable test app only in a local lab environment.

## Reporting Security Issues

If you find a security issue in Heimdall itself, please report it privately if possible. If private reporting is not available, open a GitHub issue with minimal reproduction details and no sensitive data.

Include:

- affected version or commit,
- what component is affected,
- safe reproduction steps,
- expected impact,
- suggested mitigation if known.

Do not include real API keys, tokens, passwords, production URLs, or exploit data from systems you do not own.
