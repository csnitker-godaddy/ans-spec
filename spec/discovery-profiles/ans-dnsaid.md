# Discovery profile: `ANS_DNSAID`

Status: DRAFT v1.0
Profile: ANS_DNSAID (the DNS-AID-aligned SVCB family)
Core: [ANS-3: DNS Publication](../ans-3-dns-publication.md)
Version: 0.1.0
Date: 2026-06-29
Audience: implementers building an ANS-conformant Registration Authority

`ANS_DNSAID` is the default V2 discovery profile. It emits one RFC 9460 SVCB record per protocol
endpoint at the agent's FQDN, using DNS-AID draft-02 parameters and the family trust records in
[ANS-3 §6.3](../ans-3-dns-publication.md#63-family-trust-records).

## 1. Records, labels, and selection

- **Selection**: the `ANS_DNSAID` token in `discoveryProfiles`; the default when the set is omitted or
  empty ([ANS-3 §6.4](../ans-3-dns-publication.md#64-composition-ordering-dedup-and-the-required-flag-transition)).
- **Records** (one per endpoint, emitted only when the registration has at least one endpoint):
  one **SVCB** row at the bare `{fqdn}` (apex), in ServiceMode.
- Plus the family trust records — `_ans-badge` TXT and the server-cert TLSA (ANS-3 §6.3). This
  profile emits **no** HTTPS RR; the SVCB row is itself the service binding.

## 2. Record assembly

One SVCB row per endpoint, value composed in **ascending SvcParamKey order**:

```text
1 . alpn={token} port={n} [key65400={metadataUrl}] [key65401={cap-sha256}] key65402={token} [key65409={wk-suffix}]
```

- `1 .` — SvcPriority `1` (ServiceMode), TargetName `.` (the origin — the owner name itself).
- `alpn={token}` — the DNS-AID protocol token (§3): `a2a`, `mcp`, or `x-http`. It distinguishes
  protocols within the same RRset. (This carries the DNS-AID agent-protocol token, not an
  IANA-registered TLS ALPN identifier.)
- `port={n}` — the TCP port from the endpoint URL authority; defaults to `443` (https) / `80`
  (http) when the URL omits one.
- `key65400={metadataUrl}` (DNS-AID `cap`) — the endpoint's capability locator (`metadataUrl`),
  emitted **only** when the endpoint supplies one.
- `key65401={cap-sha256}` (DNS-AID `cap-sha256`) — `base64url(raw SHA-256)` of the endpoint's
  metadata document, derived from the endpoint's `metadataHash`. Absent when no hash is supplied
  (or it is malformed).
- `key65402={token}` (DNS-AID `bap`) — the agent protocol, emitted on **every** row.
- `key65409={wk-suffix}` (DNS-AID `well-known`) — the RFC 8615 suffix derived from `metadataUrl`,
  emitted **only** when the `metadataUrl` sits at `https://{fqdn}/.well-known/{suffix}` (§3).

**Private-Use presentation form is mandatory.** The DNS-AID draft's named params
(`cap` / `cap-sha256` / `bap` / `well-known`) have no IANA-assigned code point, so they MUST be
emitted in the `keyNNNNN` presentation form (RFC 9460 §2.1). `key65400`–`key65409` sit in the
RFC 9460 §14.3.1 Private Use range (65280–65534) and match DNS-AID draft-02 §4's IANA-Considerations
assignments.

`mandatory=`, `ipv4hint`, and `ipv6hint` are not emitted (`mandatory=` would hide the record from
generic RFC 9460 clients).

## 3. Parameter sources and selection

- `alpn` / `bap` ← the endpoint's protocol, mapped to the DNS-AID token: `A2A`→`a2a`, `MCP`→`mcp`,
  `HTTP_API`→`x-http` (DNS-AID built-ins are `a2a`/`mcp`; every other token MUST be `x-`-prefixed;
  `ANS_TXT` uses `http-api` for the same protocol).
- `port` ← the endpoint URL authority; `443` (https) / `80` (http) default. An out-of-range port is
  rejected at registration (`INVALID_ENDPOINT`).
- `key65400` (cap) ← the endpoint's `metadataUrl`, emitted verbatim.
- `key65401` (cap-sha256) ← the endpoint's `metadataHash` (`SHA256:<64 lowercase hex>`), converted
  to `base64url(raw 32 bytes)`, no padding.
- `key65409` (well-known) ← derived from the `metadataUrl` path, and only when the URL is exactly
  `https://{fqdn}/.well-known/{suffix}`: same scheme (https), same host as the agent FQDN
  (port-, case-, and trailing-dot-insensitive), and a single non-empty trailing path segment. Any
  other shape omits the SvcParam.

## 4. Required flag and TL seal

| Record | Required | Note |
| --- | --- | --- |
| `{fqdn}` SVCB | **Yes**, alone; **No** in the `ANS_TXT` union | `Required=true` when `ANS_DNSAID` is the sole resolved profile; `Required=false` when `ANS_TXT` is also resolved, so the `_ans` TXT carries the required signal in the transition union (ANS-3 §6.4) |
| `_ans-badge` TXT (family) | Yes | ANS-3 §6.3 |
| `_{port}._tcp.{fqdn}` TLSA (family) | No | ANS-3 §6.3; verify-side enforces a match only when the zone is DNSSEC-validated |

Every emitted record carries TTL `3600`. The composed set is sealed verbatim into the
`AGENT_REGISTERED` attestation's `dnsRecordsProvisioned[]`
([ANS-3 §3](../ans-3-dns-publication.md#3-record-set-and-child-label-structure)). A Private-Use key
collision with an unrelated use of the same code point can only cause a false negative at
verify-dns, never a false accept.

## 5. Freshness and ANS-5 monitoring

ANS-5's DNS check re-queries the SVCB row and compares the expected SvcParams to the live record by
value equality ([ANS-5 §4](../ans-5-integrity-monitoring.md#4-verification-checks)).

## 6. Lifecycle specifics

Records are per-registration; on revocation the AHP removes the records the RA's response lists
([ANS-1 §7](../ans-1-registration.md#7-lifecycle-operations)).

## 7. Coexistence and presentation safety

- A CNAME at the apex blocks the SVCB row (ANS-3 §8.3).
- Generic SVCB clients ignore SvcParams they do not recognize (RFC 9460 §8), so ANS SvcParams coexist
  with others on the row.
- **Presentation safety** — `metadataUrl` is validated at registration to be an `https` URL,
  ≤2048 characters, and free of every byte the SVCB presentation format escapes (whitespace, double
  quote, backslash, semicolon, and non-printable ASCII) in **both** the raw URL (which feeds `cap`)
  and its percent-decoded path (which feeds `well-known`). A violation is rejected with
  `INVALID_ENDPOINT`.

## 8. Error codes

| Code | Meaning |
| --- | --- |
| `INVALID_ENDPOINT` | `metadataUrl` not https / over 2048 chars / carrying SVCB-unsafe bytes (raw or decoded path); `metadataHash` not `SHA256:<64 hex>`; `metadataHash` supplied without `metadataUrl`; `agentUrl` port outside 1–65535 |
| `INVALID_DISCOVERY_PROFILE` | (core) a `discoveryProfiles` element naming no supported profile (ANS-3 §6.4) |

## 9. Status and requirement

**Requirement: Default on V2.**

**Status: Active.** Implemented and tested, emitting the SVCB records verified at verify-dns.

## 10. Object schemas (worked example)

A multi-protocol agent — one A2A endpoint with a `/.well-known/` metadata document plus its hash,
and one MCP endpoint with neither — at version `1.0.0`, with a server certificate on file. The
sample hash `SHA256:098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27` renders as the
base64url digest below:

```text
; one SVCB row per endpoint, at the bare FQDN, in endpoint order
agent.example.com.            3600 IN SVCB  1 . alpn=a2a port=443 key65400=https://agent.example.com/.well-known/agent-card.json key65401=CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc key65402=a2a key65409=agent-card.json
agent.example.com.            3600 IN SVCB  1 . alpn=mcp port=443 key65402=mcp

; family trust records (ANS-3 §6.3) — shared with any sibling profile, deduped once
_ans-badge.agent.example.com. 3600 IN TXT   "v=ans-badge1; version=v1.0.0; url=https://transparency-log.example.com/v1/agents/{agentId}"
_443._tcp.agent.example.com.  3600 IN TLSA  3 0 1 {server-cert-sha256}
```

The sealed `dnsRecordsProvisioned[]` entry's `purpose` is `DISCOVERY` for the SVCB row.
