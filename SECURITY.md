# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.3.0 alpha line (current Core 0.7 recorder) | Current security fixes |
| 0.2.x and earlier | Historical compatibility only |

The package remains an experimental prerelease. See [release notes](RELEASE-NOTES.md) for the current patch. Historical signed records must retain their original format and explicitly selected reader; a version change does not upgrade those records.

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Email: signal@humanjudgment.org

## Scope

Relevant issues include:

- event signature bypass;
- event hash tampering;
- unsafe log handling;
- accidental data leakage;
- insecure evidence reference handling;
- dependency chain manipulation.

## Boundary

Agent Blackbox records local runtime trace artifacts.

It does not provide authorization, sandboxing, legal compliance, or complete-log guarantees.
