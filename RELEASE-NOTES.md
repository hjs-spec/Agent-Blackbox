# Release 0.2.0a2

Publish the distribution as `agent-blackbox-jep`, matching the owner's configured PyPI trusted publisher. The previous `agent-blackbox` distribution name is unavailable on PyPI.

- Update package metadata, installation instructions, and the composite Action's pinned package installation.
- Preserve Python imports (`agent_blackbox`), command names (`agent-blackbox`, `blame-finder`), event audiences, stored trace formats, and runtime behavior.
- Retain the existing GitHub release `v0.2.0a1`; this release creates new versioned artifacts instead of replacing it.

Includes the previously reviewed integrity, replay, persistence and compatibility repairs. See HARDENING.md for verification scopes and migration boundaries.
