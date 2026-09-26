# Release 0.3.0a1

Alpha release of the JEP Core 0.7 trace recorder.

- Fresh events use stable `(who,id)`, detached Ed25519 JWS and JCS; imported historical signed members remain preserved.
- Event Hash continues to identify exact signed artifacts; local trace links and incident review do not establish causal or legal conclusions.
- Signature verification requires a protected non-empty key identifier.
- The composite Action installs this distribution version and passes inputs through environment variables.
- Release metadata is checked against both built distributions before publication.

Package: `agent-blackbox-jep`; Python import: `agent_blackbox`. This is an experimental alpha, not a full trust-profile or HJS/JAC conformance claim.
