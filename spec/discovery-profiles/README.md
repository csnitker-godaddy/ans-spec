# DNS discovery profiles

Each ANS **DNS discovery profile** is one named DNS record family the RA can emit for an agent
registration. A profile specifies which records an operator publishes, at which labels, in what
wire form, and which of them are required. The core contract —
[ANS-3: DNS Publication](../ans-3-dns-publication.md) — never changes when a profile is added,
amended, or retired; that is the point of the split.

This index mirrors the registry table in
[ANS-3 §6.1](../ans-3-dns-publication.md#61-the-discovery-profile-registry). The authoritative
status is the ANS-3 table; this page is a convenience map.

| Profile | Document | Requirement | Discovery records | Status |
| --- | --- | --- | --- | --- |
| `ANS_TXT` | [ans-txt.md](ans-txt.md) | Optional (opt-in) | `_ans` TXT (one per endpoint) + an HTTPS RR at the FQDN | Active |
| `ANS_DNSAID` | [ans-dnsaid.md](ans-dnsaid.md) | Default | SVCB (one per endpoint) at the FQDN, DNS-AID SvcParams | Active |

**Requirement.** `ANS_DNSAID` is the one default profile: a registration that omits
`discoveryProfiles` (or sends an empty array) is emitted as `["ANS_DNSAID"]`, now that the
DNS-AID-aligned SVCB shape is at conformance. `ANS_TXT` is **opt-in** — an operator names it
explicitly, alone or in the `["ANS_DNSAID", "ANS_TXT"]` transition union — supported indefinitely
for operators whose zone-edit tooling targets `_ans.{fqdn}`; the V1 lane never consults the default
and is always pinned to `ANS_TXT`
([ANS-3 §6](../ans-3-dns-publication.md#6-discovery-profiles)). `discoveryProfiles` is **set
semantics on the wire**: request order carries no meaning, and emission order on the wire is the
canonical order in ANS-3 §6.4. Optional to adopt; mandatory in execution
once a profile is enabled — the RA verifies at verify-dns exactly the record set the chosen profiles
emit.

**Status meanings** (ANS-3 §6.1):

- **Active** — implemented and tested, emitting real records an operator publishes and the RA verifies at
  verify-dns.
- **Default / Opt-in** is the *requirement* axis, not the status: both bundled profiles are Active.
  `ANS_DNSAID` is the default set; `ANS_TXT` is Active but opt-in (the operator must name it).
- A `discoveryProfiles` element that names no supported profile is rejected at the API boundary with
  `INVALID_DISCOVERY_PROFILE`; an unknown *stored* profile is omitted from the resolved set, and an
  all-unknown stored set falls back to the default. Partial omission and all-unknown fallback MUST
  be diagnosable and distinguishable to the operator (ANS-3 §6.4).

## The profile template

Every discovery-profile document specifies, in this order (ANS-3 §6.2):

1. Records, labels, and selection — which records the profile emits, at which labels, and how the
   profile is selected (its `discoveryProfiles` ID).
2. Record assembly — the exact value form and parameter composition, in order.
3. Parameter sources — where each field's value comes from, and the selection rules.
4. Required flag and TL seal — which records are required, the union's flags, and what the profile
   seals into `dnsRecordsProvisioned[]`.
5. Freshness and ANS-5 monitoring.
6. Lifecycle (version coexistence, revocation cleanup).
7. Coexistence and presentation safety.
8. Error codes.
9. Status and requirement.
10. Object schemas — worked record examples.

All ANS-family profiles share the two **family trust records** — the `_ans-badge` TXT and the
server-cert TLSA (ANS-3 §6.3) — present for each profile alone and deduplicated in the composed set.
A profile only ever varies the **discovery records** layered on top of that
shared base.

## Conformance artifacts

The `discoveryProfiles` request field and the `DiscoveryProfile` enum — the closed `ANS_DNSAID` /
`ANS_TXT` set, `minItems: 1`, `uniqueItems: true`, default `["ANS_DNSAID"]` — are specified in
[ANS-3 §6](../ans-3-dns-publication.md#6-discovery-profiles) and carried as the `DiscoveryProfile`
schema and `discoveryProfiles[]` field in the RA's OpenAPI document. The composed record set is
sealed verbatim into the `AGENT_REGISTERED` attestation as `dnsRecordsProvisioned[]`; its
field-by-field contract is
[ANS-3 §3](../ans-3-dns-publication.md#3-record-set-and-child-label-structure). Every profile permitted
by the API MUST be supported for generation and verification, and every generated profile MUST be
permitted by that API. The RA MUST NOT serve registration operations under an inconsistent
configuration and MUST make inconsistencies diagnosable to its operator
([ANS-3 §6.4](../ans-3-dns-publication.md#64-composition-ordering-dedup-and-the-required-flag-transition)).
