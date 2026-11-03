# Identity profiles

Each profile defines an identifier kind's selection, control proof, key source, sealed evidence,
and monitoring rules. The authoritative registry, applicability, and maturity definitions are in
[ANS-0 §10.1](../ans-0-identity-anchor.md#101-the-profile-registry); required profile content is in
[§10.2](../ans-0-identity-anchor.md#102-what-a-profile-must-define).

| Kind | Profile |
| --- | --- |
| `fqdn` (agent primary anchor) | [fqdn.md](fqdn.md) |
| `did:web` | [did-web.md](did-web.md) |
| `did:key` | [did-key.md](did-key.md) |
| `lei` | [lei.md](lei.md) |
| `did:plc` | [did-plc.md](did-plc.md) |
| `did:ethr` / `did:pkh` | [did-ethr.md](did-ethr.md) |
| `did:ion` | [did-ion.md](did-ion.md) |
| `ens` | [ens.md](ens.md) |

All profiles use the [ANS-0 proof-of-control gate](../ans-0-identity-anchor.md#3-the-proof-of-control-gate).
The Verified Identity capability is optional under
[ANS-0 §12.2](../ans-0-identity-anchor.md#122-optional-capability-verified-identities).

## Conformance artifacts

- [Identity-event JSON Schema](../../api/identity-event-schema-v2.json).
- [Sealed fields and per-type requirements](../ans-0-identity-anchor.md#81-the-identity-event-family-and-ingest).
- [TL envelope example](../examples/ans-4-examples.md#a1-sealed-envelope-and-append-response).
- Per-kind request, challenge, and sealed-key examples in Active and Postponed profiles' Object schemas sections.
