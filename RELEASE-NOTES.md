# Release 0.3.0a2

- Preserve JCS signatures and hashes when exactly representable large numbers arrive as integer tokens after JavaScript serialization.
- Reject integers that would lose precision on conversion to the JCS binary64 number domain.

This remains an alpha incident recorder with local JAC/HJS conventions. Core protocol and historical signed artifacts are unchanged.
