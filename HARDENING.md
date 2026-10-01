# Canonical signed records and async tracing

New events use RFC 8785 JCS; imported events preserve signed member presence and field types. Verification checks the JOSE header and rejects identity-key forgeries using PyNaCl/libsodium. Legacy json.dumps signatures require explicit verify(..., legacy=True); no silent fallback or rewriting of historical logs occurs.

Async traces await execution and record cancellation/failure. Informational JAC links are not falsely marked critical. The trace decorator emits judgments; D/T/V require explicit events with their required fields. Verification also checks that the stored event hash still matches the lookup key.

Keys and in-memory trace indexes remain local to a recorder instance; this alpha recorder is not a managed multi-process identity service. Retain/export trusted public keys for independent historical verification. Regression tests cover exact signed round trips, Unicode/floats, malformed crypto inputs, and awaited/cancelled traces.

## Event extensions and imports

Declared dependency links use `ext["https://jac.org/chain"]`. Input, output and
error digests use `ext["https://hjs.org/evidence-refs"]`. These identifiers are
part of the recorded format and must be preserved when exporting signed events.
When a recorded parent is available locally, the Core `ref` uses a typed
`jep:event` reference with Event Identity and an optional exact-artifact hash.
Chain reconstruction, causality, authority and termination cascade are not Core
verification results.

Fresh events do not add a mandatory Core nonce. Imported pre-0.7 events retain
their original signed members, including a historical `nonce` when present;
importing a record does not convert its protocol version.
