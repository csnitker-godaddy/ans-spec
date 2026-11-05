# Identity profile: `did:plc` (deferred sketch)

Status: DRAFT v1.0 — deferred sketch
Profile: did:plc
Core: [ANS-0: Identity](../ans-0-identity-anchor.md)
Version: 0.0.1
Date: 2026-06-23
Audience: implementers evaluating future identifier kinds

> **Deferred.** This documents the intended shape only. It ships when its resolver, tests, and
> external plumbing are real — until then the kind is unregistered and returns
> `IDENTIFIER_KIND_UNSUPPORTED` (the 404-is-the-signal rule, ANS-0 §10.1). No placeholder seal.

**Requirement: Optional** ([ANS-0 §12.2](../ans-0-identity-anchor.md#122-optional-capability-verified-identities)).

`did:plc` is AT Protocol's self-authenticating, directory-resolved DID method. It fits the
existing JWS-scheme, multi-key, fetch-based pattern almost exactly — the same shape as
[`did:web`](did-web.md), differing only in the key source.

- **Identifier / selection**: `did:plc:<base32 hash>`; lexical (`did:plc:` prefix). Canonical
  form is the lowercased method-specific id (fixed length).
- **Key source**: the DID document resolved from a PLC directory (default `plc.directory`),
  listing `verificationMethod`/`assertionMethod` keys (secp256k1 / P-256) plus PLC rotation keys.
  Fetch-based — same egress rules and verify checks as did:web (resolve at verify
  time, `document.id == did`, per-`kid` assertionMethod selection, alg-pinned signature).
- **Control axis**: key only — possession of one or more listed `assertionMethod` keys, proven
  with the shared `signedProofs[]` JWS machinery.
- **Seal tier**: verbatim verification method (ANS-0 §8.4), like did:web.
- **Freshness/monitoring**: ANS-5 re-resolves the PLC log/directory; the signal is key-set drift
  and the PLC operation log's tamper-evidence (a did:plc audit log is itself append-only).
- **SSRF**: directory fetch is registrant-influenced (the directory host is fixed, but a
  self-hosted PLC mirror is steerable) → same egress rules as did:web.
