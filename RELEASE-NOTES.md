# Software 0.3.0a4

Simplify the installation and incident-review entry points. Describe the package
and GitHub Action by their supported tasks, and move event-format and import
details to the technical notes. Runtime behavior, extension identifiers, signed
records and Core 0.7 semantics are unchanged.

# Software 0.3.0a3

Complete the JCS numeric roundtrip repair: accept the canonical shortest decimal spelling of a binary64 number as well as its exact integer value. For example, JavaScript emits `1000000000000000100` for the float whose exact integer value is `1000000000000000128`. Both serialize to the same JCS bytes. Noncanonical precision-losing integers and overflow remain rejected.

Regression coverage includes positive and negative shortest-form numbers, exact large integers, real signatures and unchanged Event Hashes. Published normative artifacts remain unchanged.

# Release 0.3.0a2

- Preserve JCS signatures and hashes when exactly representable large numbers arrive as integer tokens after JavaScript serialization.
- Reject integers that would lose precision on conversion to the JCS binary64 number domain.

This remains an alpha incident recorder with local JAC/HJS conventions. Core protocol and historical signed artifacts are unchanged.
