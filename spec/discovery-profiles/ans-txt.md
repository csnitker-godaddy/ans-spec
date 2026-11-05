# Discovery profile: `ANS_TXT`

Status: DRAFT v1.0
Profile: ANS_TXT (the original `_ans` TXT family)
Core: [ANS-3: DNS Publication](../ans-3-dns-publication.md)
Version: 0.1.0
Date: 2026-06-29
Audience: implementers building an ANS-conformant Registration Authority

`ANS_TXT` emits `_ans` TXT discovery records and an HTTPS connection hint. It is opt-in on V2,
pinned on V1, and supported indefinitely. Selection and composition follow
[ANS-3 §6](../ans-3-dns-publication.md#6-discovery-profiles).

## 1. Records, labels, and selection

- **Selection**: the `ANS_TXT` token in the registration's `discoveryProfiles` set. Opt-in on the
  V2 lane — an operator names it explicitly, alone or in the `["ANS_DNSAID", "ANS_TXT"]` transition
  union; the V1 lane is pinned to it regardless of request
  ([ANS-3 §6.4](../ans-3-dns-publication.md#64-composition-ordering-dedup-and-the-required-flag-transition)).
- **Records** (emitted only when the registration has at least one endpoint):
  - one `_ans.{fqdn}` **TXT** discovery record per endpoint, at the `_ans` child label;
  - one **HTTPS** RR at the bare `{fqdn}` (apex), as the connection hint `_ans` TXT cannot carry.
- Plus the family trust records — `_ans-badge` TXT and the server-cert TLSA (ANS-3 §6.3).

## 2. Record assembly

**`_ans` TXT discovery record**, one per endpoint, value built in this fixed field order:

```text
v=ans1; version=v{version}; p={protocol-token}; mode=direct; url={agentUrl}
```

- `v` — always `ans1`.
- `version` — the registration's semantic version, **prefixed with `v`** (e.g. `v1.0.0`), matching
  the ANSName's version segment (ANS-2).
- `p` — the protocol token (§3): `a2a`, `mcp`, or `http-api`.
- `mode` — always `direct` on every emitted row.
- `url` — the endpoint's `agentUrl`, verbatim.

**HTTPS RR**, one per registration, at the bare `{fqdn}`:

```text
1 . alpn=h2
```

SvcPriority `1` (ServiceMode), TargetName `.` (the origin — the owner name itself), `alpn=h2`
(HTTP/2 service binding).

## 3. Parameter sources and selection

- `version` ← the registration's version, rendered with the `v` prefix (§2).
- `p` ← the endpoint's protocol, mapped to the `_ans` token: `A2A`→`a2a`, `MCP`→`mcp`,
  `HTTP_API`→`http-api`.
- `url` ← the endpoint's `agentUrl`.
- `mode` ← the constant `direct`.

## 4. Required flag and TL seal

| Record | Required | Note |
| --- | --- | --- |
| `_ans.{fqdn}` TXT | **Yes** | The discovery record. verify-dns blocks activation until it resolves to the announced content |
| `{fqdn}` HTTPS RR | No | A CNAME at the apex precludes publishing an HTTPS RR (RFC 1034 §3.6.2); its absence is non-fatal |
| `_ans-badge` TXT (family) | Yes | ANS-3 §6.3 |
| `_{port}._tcp.{fqdn}` TLSA (family) | No | ANS-3 §6.3; verify-side enforces a match only when the zone is DNSSEC-validated |

Every emitted record carries TTL `3600`. The composed set is sealed verbatim into the
`AGENT_REGISTERED` attestation's `dnsRecordsProvisioned[]`
([ANS-3 §3](../ans-3-dns-publication.md#3-record-set-and-child-label-structure)).

## 5. Freshness and ANS-5 monitoring

ANS-5's DNS check re-queries these records
([ANS-5 §4](../ans-5-integrity-monitoring.md#4-verification-checks)).

## 6. Lifecycle specifics

Records are per-registration; on revocation the AHP removes the records the RA's response lists
([ANS-1 §7](../ans-1-registration.md#7-lifecycle-operations)).

## 7. Coexistence and presentation safety

- A CNAME at the apex blocks the HTTPS RR (ANS-3 §8.3); the `_ans` child label is unaffected.
- `_ans` TXT values carry none of the SVCB presentation constraints.

## 8. Error codes

This profile defines no codes of its own. Endpoint validation surfaces the core `INVALID_ENDPOINT`,
`ENDPOINT_HOST_MISMATCH`, `DUPLICATE_ENDPOINT`, and `DUPLICATE_PROTOCOL` errors (ANS-1); an unknown
`discoveryProfiles` element is `INVALID_DISCOVERY_PROFILE` (ANS-3 §6.4).

## 9. Status and requirement

**Requirement: Optional (opt-in) on V2; pinned on V1.**

**Status: Active.** Implemented, sealing and verifying the records defined here.

## 10. Object schemas (worked example)

A single A2A endpoint at `https://agent.example.com/a2a`, version `1.0.0`, with a server certificate
on file:

```text
; discovery record — one per endpoint
_ans.agent.example.com.        3600 IN TXT   "v=ans1; version=v1.0.0; p=a2a; mode=direct; url=https://agent.example.com/a2a"

; connection hint — one per registration, at the apex
agent.example.com.             3600 IN HTTPS 1 . alpn=h2

; family trust records (ANS-3 §6.3) — shared with any sibling profile, deduped once
_ans-badge.agent.example.com.  3600 IN TXT   "v=ans-badge1; version=v1.0.0; url=https://transparency-log.example.com/v1/agents/{agentId}"
_443._tcp.agent.example.com.   3600 IN TLSA  3 0 1 {server-cert-sha256}
```

The sealed `dnsRecordsProvisioned[]` entries carry the same `{name, type, value, purpose, required,
ttl}` shape the operator publishes; `purpose` is `DISCOVERY` for the `_ans` TXT and HTTPS RR, `BADGE`
for `_ans-badge`, and `CERTIFICATE_BINDING` for the TLSA.
