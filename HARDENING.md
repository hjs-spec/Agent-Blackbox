# Canonical signed records and async tracing

New events use RFC 8785 JCS; imported events preserve signed member presence and field types. Verification checks the JOSE header and rejects identity-key forgeries using PyNaCl/libsodium. Legacy json.dumps signatures require explicit verify(..., legacy=True); no silent fallback or rewriting of historical logs occurs.

Async traces await execution and record cancellation/failure. Informational JAC links are not falsely marked critical. The trace decorator emits judgments; D/T/V require explicit events with their required fields. Verification also checks that the stored event hash still matches the lookup key.

## Reopening a recorder

Opening a recorder rebuilds its index from a locked snapshot of `events.jsonl`.
Each append takes the same journal lock. Reopen a long-lived reader to see
another process's subsequent writes. Each restored row must match its signed
event hash and the metadata used for review. A malformed row stops loading
with its line number, so a partial journal cannot silently yield a clean review.

The recorder generates an Ed25519 signing key for each actor per recorder
instance. Only the 32-byte public key is saved, before its first event is
appended. The signed key ID contains the SHA-256 digest of the public key.
Restarted writers generate new keys and retain earlier public keys. The default
public key directory is `<storage>/trusted-keys/`. Keep it with your backups.
Historical journals created without persisted keys remain inspectable. Their
signatures require the original, independently retained public keys. Missing
keys report `unknown_key`.

Local verification assumes that only trusted recorders can populate the key
directory. To verify an imported journal, supply an independently provisioned
directory via `--trusted-keys` or the Action's `trusted_keys_path`. Each
`.pub` filename is the lower-case SHA-256 hex digest of the RFC 8785 encoding
of `[who, kid]`, followed by `.pub`. Treat the writable journal and its
co-located key directory as one trust domain. Verification covers event
integrity under the supplied keys. The journal alone cannot establish signer
identity or completeness.

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
