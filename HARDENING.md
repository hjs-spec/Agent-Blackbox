# Canonical signed records and async tracing

New events use RFC 8785 JCS; imported events preserve signed member presence and field types. Verification checks the JOSE header and rejects identity-key forgeries using PyNaCl/libsodium. Legacy json.dumps signatures require explicit verify(..., legacy=True); no silent fallback or rewriting of historical logs occurs.

Async traces await execution and record cancellation/failure. Informational JAC links are not falsely marked critical. The trace decorator emits judgments; D/T/V require explicit events with their required fields. Verification also checks that the stored event hash still matches the lookup key.

Keys and in-memory trace indexes remain local to a recorder instance; this alpha recorder is not a managed multi-process identity service. Retain/export trusted public keys for independent historical verification. Regression tests cover exact signed round trips, Unicode/floats, malformed crypto inputs, and awaited/cancelled traces.
