# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in AgentShield, please report it
responsibly:

1. **GitHub Security Advisories** (preferred): Use the
   [private vulnerability reporting](https://github.com/Jamessheung/agentshield/security/advisories/new)
   feature on GitHub.

2. **GitHub Issues**: Open an issue with the `security` label if the
   vulnerability is not sensitive (e.g., a false-negative in detection rules).

Please include:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

## Response Timeline

- **Acknowledgement**: within 48 hours
- **Initial assessment**: within 1 week
- **Fix release**: critical issues within 2 weeks, others within 30 days

## Scope

The following are in scope for security reports:

- **False negatives**: malicious patterns that bypass AgentShield's detection
- **False positives**: clean skills incorrectly flagged as malicious
- **Web API vulnerabilities**: injection, authentication bypass, DoS, etc.
- **Supply chain risks**: in AgentShield's own dependencies
- **GitHub Action security**: issues in the composite action workflow

## Disclosure Policy

We follow coordinated disclosure. Please allow us reasonable time to fix
vulnerabilities before public disclosure.
