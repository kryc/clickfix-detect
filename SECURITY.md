# Security policy

## Supported versions

Security fixes are developed on the `main` branch. Users should run the latest
published revision because this project models rapidly changing payload and
parser behavior.

## Reporting a vulnerability

Please report vulnerabilities privately through the repository's
**Security > Report a vulnerability** workflow. Do not open a public issue for
a suspected sandbox escape, native-code execution path, denial-of-service
condition, SSRF bypass, trust-policy bypass, or sensitive-data exposure.

Include:

- the affected commit and component;
- a minimal, safely defanged reproducer;
- the expected and observed behavior;
- whether native processes, the host filesystem, registry, or unrestricted
  network access can be reached;
- any resource-exhaustion measurements.

Do not include live credentials, active malware infrastructure, or harmful
payloads. The maintainers will acknowledge a complete report, assess impact,
and coordinate remediation and disclosure through the private advisory.

## Security boundaries

The intended boundary is hermetic interpretation:

- native payloads are inspected but never loaded or executed;
- files and registry state remain in memory;
- network access is disabled by default and bounded to public HTTP(S) when
  explicitly enabled;
- parser, decode, process, file, artifact, trace, provenance, and binary
  inspection work is resource-limited.

Behavior that crosses one of these boundaries should be treated as a security
issue even when the analyzed input is intentionally malicious.
