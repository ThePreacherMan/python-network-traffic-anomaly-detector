# Security Policy

## Supported Versions

The latest release of the Python Network Traffic Anomaly Detector is the currently supported version.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Older releases | Best effort |
| Development branch | Not guaranteed |

## Reporting a Vulnerability

Please do not publicly disclose suspected security vulnerabilities through a standard GitHub issue.

Report security concerns privately by contacting the project maintainer through GitHub or LinkedIn.

When reporting a vulnerability, include:

- A clear description of the issue
- The affected file, function, or component
- Steps to reproduce the issue
- The potential security impact
- Any suggested remediation
- Relevant screenshots, logs, or proof-of-concept details

Do not include real credentials, sensitive network data, personal information, or confidential customer information.

## Response Process

Security reports will be reviewed as soon as reasonably possible.

The review process may include:

1. Confirming receipt of the report
2. Reproducing and validating the issue
3. Assessing severity and impact
4. Developing and testing a fix
5. Publishing a patched release
6. Crediting the reporter when appropriate

## Scope

Security issues may include:

- Unsafe input handling
- CSV parsing weaknesses
- Command-line injection risks
- Dependency vulnerabilities
- Sensitive-data exposure
- Insecure file handling
- Unexpected code execution
- Incorrect validation behavior
- Denial-of-service risks

## Out of Scope

The following are generally outside the scope of this security policy:

- False positives produced by detection rules
- Expected limitations documented in the README
- Issues caused by unsupported Python versions
- Problems caused by modified third-party code
- Reports without enough information to reproduce the issue

## Responsible Disclosure

Please allow reasonable time for investigation and remediation before publicly discussing a confirmed vulnerability.

This project is intended for defensive security education, portfolio development, and authorized experimentation only.
