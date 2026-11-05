# ANS-3: DNS Publication

Status: DRAFT v1.0
Spec: ANS-3 (DNS Publication)
Version: 0.1.0
Date: 2026-06-29
Audience: implementers building or operating an ANS Registration Authority that emits DNS records and the AHPs that provision them

## 1. Scope

ANS-3 defines the DNS records an RA generates for a registration, the records its operator
publishes, and the checks required before activation. Records use the registration's `agentHost`
or its child labels.

Discovery profiles are defined in §6.

[ANS-1](ans-1-registration.md) and [ANS-2](ans-2-versioned-naming.md) govern certificates;
[ANS-5](ans-5-integrity-monitoring.md) governs ongoing DNS and DANE verification.

## 2. DNS record-generation contract

A discovery profile is identified by its `DiscoveryProfile` wire value (`ANS_TXT`, `ANS_DNSAID`)
and defines the records the operator must publish for the registration. For the same registration,
selected profiles, and TTL policy, the RA MUST produce the same record content, required flags,
and canonical order, independent of the request order of `discoveryProfiles`. Each selected profile
alone MUST produce its discovery records and complete shared family trust records (§6.3).

Composition, validation, and stored-profile fallback follow §6.4; the resulting order is preserved in
`dnsRecordsProvisioned[]` and in byte-identical event retries.

## 3. Record set and child-label structure

The RA generates record content for the agent's `agentHost` and for child labels under it; the AHP
or domain owner provisions the records. Child-label records coexist with an A, AAAA, or CNAME at the
FQDN; apex SVCB/HTTPS records follow RFC 9460 §3.

| Record | Label | Type | Profile | Purpose | Required |
| --- | --- | --- | --- | --- | --- |
| Discovery (`_ans` TXT) | `_ans.{agentHost}` | TXT | `ANS_TXT` (opt-in) | One per endpoint: protocol token + endpoint URL ([ans-txt](discovery-profiles/ans-txt.md)) | Yes |
| Discovery (SVCB) | `{agentHost}` | SVCB | `ANS_DNSAID` (default) | One per endpoint: DNS-AID SvcParams ([ans-dnsaid](discovery-profiles/ans-dnsaid.md)) | Yes (No in the `ANS_TXT` union, §6.4) |
| Connection hint (HTTPS RR) | `{agentHost}` | HTTPS | `ANS_TXT` | `1 . alpn=h2` service binding | No (CNAME at apex precludes it) |
| Badge | `_ans-badge.{agentHost}` | TXT | family (every profile) | TL badge URL for verification (§6.3) | Yes |
| Server DANE | `_{port}._tcp.{agentHost}` | TLSA | family (every profile) | Server Certificate fingerprint (`3 0 1`, selector 0); one per distinct TLS endpoint port (§6.3) | No (verify-side enforces a match when DNSSEC-validated) |

When the last ACTIVE version for an `agentHost` is revoked, the AHP removes all ANS records it
provisioned for that FQDN. The RA's revocation response lists the records to delete (see
[ANS-1 §6.2](ans-1-registration.md#62-agent_revoked) for the revoke event payload).

### 3.1 Discoverer fallback chain

A discoverer walks two sources in order when assembling an agent's metadata, stopping at the first source that resolves and verifies:

1. Query DNS for the registration's discovery records. With `ANS_DNSAID`, read the SVCB
   row at `agentHost` and follow its per-endpoint capability locator (`key65400` / `key65409`); with
   `ANS_TXT`, read the `_ans.{agentHost}` TXT records and follow each row's `url` (`mode=direct`).
   Use the record if reachable and DNSSEC-valid, or DNSSEC-unsigned and operator-acceptable.
2. Otherwise, use the metadata payload from the Transparency Log event the discoverer already
   consumed from the log's event stream.

The ordering is normative.

## 4. Activation validations

Before transitioning a registration from `PENDING_DNS` to `ACTIVE`, the RA runs a conformance check
to verify the registrant has provisioned the announced records. The table below enumerates the
checks and their required outcomes. "Announced" means the records the composed profile set emitted
into `dnsRecordsProvisioned[]` for this registration.

| Record type | Validation procedure | Success criterion | Failure handling |
| --- | --- | --- | --- |
| Discovery (the `_ans.{agentHost}` TXT for `ANS_TXT`, the `{agentHost}` SVCB for `ANS_DNSAID`, per §6) | RA performs a DNS lookup for each announced discovery record at its label | Each required discovery record resolves to the announced content | Registration stays in `PENDING_DNS`; the RA retries on schedule and the registrant reconciles by publishing the announced record |
| Badge TXT | RA performs a DNS lookup for `_ans-badge.{agentHost}` | Record resolves to the announced URL | The badge is emitted `Required` (§6.3); a missing badge keeps the registration in `PENDING_DNS` until reconciled |
| Server DANE TLSA (DNSSEC-signed zones only) | RA performs a DNS lookup for each `_{port}._tcp.{agentHost}` TLSA and validates the DNSSEC chain | No DNSSEC-validated TLSA record contradicts the expected fingerprint (presence is not required; authenticated absence passes) | The TLSA is emitted `Required=false`; in a signed zone a DNSSEC-validated TLSA that does **not** match the expected fingerprint is an attack signal and blocks activation. The check is skipped in unsigned zones; the registration activates without it |

**DNSSEC result.** TLSA, SVCB, and HTTPS lookups carry the resolver's DNSSEC Authenticated-Data
result into the sealed event as `dnsRecordsProvisioned[].dnssecVerified` — `true` when the
record's query returned the AD bit, absent otherwise; TXT lookups never carry the flag
([ANS-1 §6.1](ans-1-registration.md#61-agent_registered)). A DNSSEC-validated record that
contradicts the announced content is an attack signal and blocks activation (per the TLSA row
above).

## 5. DNS management roles

The AHP owns the domain and publishes every ANS record using content the RA generates; the RA has no
DNS write access (§8.1).

## 6. Discovery profiles

A registration carries a set of discovery profiles in `discoveryProfiles`; each profile is one DNS
record family (`ANS_DNSAID` default, `ANS_TXT` opt-in). The set normalizes per §6.4 rule 1; the V1
lane never consults the default and is pinned to `["ANS_TXT"]` regardless of request. Request order
carries no meaning.

### 6.1 The discovery-profile registry

| Profile | Document | Requirement | Discovery records | Status |
| --- | --- | --- | --- | --- |
| `ANS_TXT` | [discovery-profiles/ans-txt.md](discovery-profiles/ans-txt.md) | Optional (opt-in) | `_ans` TXT (one per endpoint) + an HTTPS RR at the FQDN | Active |
| `ANS_DNSAID` | [discovery-profiles/ans-dnsaid.md](discovery-profiles/ans-dnsaid.md) | Default | SVCB (one per endpoint) at the FQDN, DNS-AID SvcParams | Active |

**Status meanings.** **Active** — implemented and tested, emitting real records an operator publishes and the
RA verifies at verify-dns. **Default / Opt-in** is the requirement axis, not the status: both
profiles are Active; `ANS_DNSAID` is the default set, and `ANS_TXT` is opt-in (the operator must
name it) — supported indefinitely.

### 6.2 The profile template

Every discovery-profile document specifies the following content:

1. Records, labels, and selection.
2. Record assembly — the exact value form and parameter composition, in order.
3. Parameter sources — where each field's value comes from, and the selection rules.
4. Required flag and what the profile seals into `dnsRecordsProvisioned[]`.
5. Freshness and ANS-5 monitoring.
6. Lifecycle (version coexistence, revocation cleanup).
7. Coexistence and presentation safety.
8. Error codes.
9. Status and requirement.
10. Object schemas — worked record examples.

### 6.3 Family trust records

Both ANS-family profiles include the following shared trust records, deduplicated in the composed
set (§6.4). Each selected profile alone still produces the complete family trust record set:

- **Badge** — `_ans-badge.{agentHost}` TXT, value `v=ans-badge1; version=v{version}; url={badgeURL}`,
  where `{version}` is the registration's semver (the value carries the `v` prefix, matching the ANSName's version segment) and `{badgeURL}` is the
  Transparency Log badge endpoint for the agent (`{tlPublicBaseURL}/v1/agents/{agentId}`), falling
  back to the agent's first endpoint URL when no public TL URL is configured. Emitted only when the
  registration has at least one endpoint. **`Required=true`**.
- **Server DANE TLSA** — `_{port}._tcp.{agentHost}` TLSA, value `3 0 1 {fingerprint}` (DANE-EE,
  full-certificate selector 0, SHA-256 — the fingerprint is SHA-256 over the full DER Server
  Certificate, matching the badge fingerprint in the TL). One record per **distinct TLS endpoint
  port** (ports sorted ascending; plaintext `http` endpoints skipped; an empty port set falls back
  to `443`). Emitted only when the registration has a server certificate. **`Required=false`**; a
  DNSSEC-validated TLSA MUST still match the expected fingerprint (§4).

### 6.4 Composition: ordering, dedup, and the required-flag transition

The composed `dnsRecordsProvisioned[]` MUST satisfy these rules:

1. **Resolved profile set.** Unknown profiles in stored registrations are omitted. An omitted or
   empty set, including an all-unknown stored set, normalizes to `["ANS_DNSAID"]`.
2. **Unique records.** The composed set MUST contain one entry per distinct `(name, type, value)`.
   Profiles producing the same record MUST agree on its `Required` flag: the shared badge is
   required and TLSA records are optional (§6.3).
3. **Canonical order.** Records MUST appear in this order: `ANS_TXT` TXT records in endpoint order,
   its HTTPS record, `ANS_DNSAID` SVCB records in endpoint order, the badge, then TLSA records in
   ascending distinct endpoint-port order. Records not emitted under the selected profiles or
   registration's applicable rules are omitted. Request order on `discoveryProfiles` has no effect.
   This order MUST be preserved in the sealed `dnsRecordsProvisioned[]` and event retries.
4. **Required flags.** SVCB records MUST have `Required=true` when `ANS_DNSAID` is the sole resolved
   profile and `Required=false` when the resolved set also includes `ANS_TXT`. The union's `_ans`
   TXT records remain required. Family record flags remain as specified in §6.3.

**Validation.** Each `discoveryProfiles` element MUST be a valid `DiscoveryProfile`; an unrecognized
value is rejected at the API boundary with `422 INVALID_DISCOVERY_PROFILE`. Duplicate elements are
deduped (first occurrence wins) and an empty array normalizes to the default — the OpenAPI
`minItems: 1` and `uniqueItems: true` are the canonical client contract, which the server normalizes
rather than rejecting. Every profile permitted by the `DiscoveryProfile` API contract MUST be
supported for record generation and verification, and every generated profile MUST be permitted by
that contract.

## 7. DNS verification modes

Activation validations (§4) MUST query live DNS, validating DNSSEC where the zone is signed. A
deployment that accepts records without querying DNS is non-conformant for any verifier it serves
externally.

## 8. Security considerations

### 8.1 RA-DNS privilege separation

The RA's DNS permissions MUST exclude TLSA write access: a compromised RA that could both issue a
Server Certificate and write the matching TLSA would defeat DANE as an independent channel. The RA
generates TLSA content; the AHP publishes it.

### 8.2 Public discoverability of DNS records

ANS-3 records MUST be published in public DNS zones, queryable by any third party via standard DNS
lookups. An implementation that publishes DNS records only to a private zone, requires authentication to
query, or uses a proprietary protocol for record lookup is non-conformant even if the record format
and content are otherwise correct.

### 8.3 CNAME blocking at the FQDN

An owner name publishing SVCB or HTTPS records MUST NOT also publish a CNAME, in accordance with
RFC 1034 §3.6.2. The `ANS_DNSAID` SVCB row and the `ANS_TXT` HTTPS RR both sit at `agentHost`.
Operators requiring aliasing behavior MUST choose a DNS arrangement that preserves the required
ANS records without a conflicting CNAME at `agentHost`. CNAME flattening is one possible
arrangement. A CNAME at `agentHost` does not affect the separate `_ans` child label, so `ANS_TXT`
discovery still functions behind an apex CNAME. When the RA detects a CNAME at `agentHost` it omits
the apex record.

### 8.4 Coexistence with other DNS records under the same FQDN

ANS SvcParams ride the SVCB row in Private-Use `keyNNNNN` form, which generic SVCB clients ignore
(RFC 9460 §8); the presentation-safety rule is in
[ans-dnsaid §7](discovery-profiles/ans-dnsaid.md#7-coexistence-and-presentation-safety). Other
agent-discovery drafts publish under different underscored leaves and do not collide with `_ans`.

## 9. Conformance

A conformant ANS-3 implementation implements §§2–8 and honors the per-version TTL parameter from
operator policy. A conforming verifier MUST NOT downgrade integrity scoring solely because an
operator chose `ANS_TXT` over `ANS_DNSAID` (or vice versa).

## References

- ANS-1 specification: [`ans-1-registration.md`](ans-1-registration.md). Registration aggregate, revocation cleanup.
- ANS-2 specification: [`ans-2-versioned-naming.md`](ans-2-versioned-naming.md). Version coexistence rules.
- ANS-5 specification: [`ans-5-integrity-monitoring.md`](ans-5-integrity-monitoring.md). Verification procedure consuming DNS records.
- Discovery profiles: [`discovery-profiles/`](discovery-profiles/) — [ANS_TXT](discovery-profiles/ans-txt.md), [ANS_DNSAID](discovery-profiles/ans-dnsaid.md).
- [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034): DNS concepts (CNAME blocking).
- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035): DNS implementation (TXT, label limits).
- [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698): DANE TLSA records.
- [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615): well-known URIs.
- [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html): SVCB and HTTPS resource records.

## Appendix A. Annotated zone-file example

A zone-file snippet for a registration running the transition union with A2A on 443 and MCP on 8443.

```text
; ========== ACME Corp ANS Agent Zone Snippet ==========
; Zone: acmecorp.com
; Agent FQDN: ai-agent.acmecorp.com
; Registration: versioned (v2.1.0); discoveryProfiles: ["ANS_DNSAID", "ANS_TXT"]
;
; Record ownership legend:
;   [RA-content]: RA generates the expected content; AHP publishes the record (discovery, badge, Server DANE)
;   [AHP]: AHP both generates content and publishes the record (A/AAAA)

; A/AAAA records (AHP)
ai-agent.acmecorp.com.        300  IN A        203.0.113.42
ai-agent.acmecorp.com.        300  IN AAAA     2001:db8::42

; ANS_TXT discovery [RA-content] — one `_ans` TXT per endpoint; version carries the `v` prefix; mode=direct
_ans.ai-agent.acmecorp.com.   3600 IN TXT      "v=ans1; version=v2.1.0; p=a2a; mode=direct; url=https://ai-agent.acmecorp.com/a2a"
_ans.ai-agent.acmecorp.com.   3600 IN TXT      "v=ans1; version=v2.1.0; p=mcp; mode=direct; url=https://ai-agent.acmecorp.com:8443/mcp"

; ANS_TXT connection hint [RA-content] — one HTTPS RR at the apex (Required=false)
ai-agent.acmecorp.com.        3600 IN HTTPS    1 . alpn=h2

; ANS_DNSAID discovery [RA-content] — one SVCB row per endpoint at the apex; DNS-AID SvcParams in
; keyNNNNN Private-Use form; Required=false here because ANS_TXT is also in the set (§6.4).
ai-agent.acmecorp.com.        3600 IN SVCB     1 . alpn=a2a port=443 key65400=https://ai-agent.acmecorp.com/.well-known/agent-card.json key65401=CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc key65402=a2a key65409=agent-card.json
ai-agent.acmecorp.com.        3600 IN SVCB     1 . alpn=mcp port=8443 key65402=mcp

; Badge TXT [RA-content] — family record; one per registration; points at the TL badge endpoint
_ans-badge.ai-agent.acmecorp.com. 3600 IN TXT  "v=ans-badge1; version=v2.1.0; url=https://transparency-log.example.com/v1/agents/550e8400-e29b-41d4-a716-446655440000"

; Server DANE TLSA [RA-content] — family record; one per distinct TLS port (443 and 8443); 3 0 1 over the full Server Certificate
_443._tcp.ai-agent.acmecorp.com.  3600 IN TLSA 3 0 1 a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
_8443._tcp.ai-agent.acmecorp.com. 3600 IN TLSA 3 0 1 a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
```
