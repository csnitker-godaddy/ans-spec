# Identity profile: `fqdn`

Status: DRAFT v1.0
Profile: fqdn (the agent's primary anchor)
Core: [ANS-0: Identity](../ans-0-identity-anchor.md)
Version: 0.1.0
Date: 2026-06-23
Audience: implementers building an ANS-conformant Registration Authority

The `fqdn` profile proves an agent's mandatory primary anchor on the ANS-1 registration path
([ANS-0 §9](../ans-0-identity-anchor.md#9-the-who-the-what-and-the-fqdn-primary-anchor)). It is not a
Verified Identity and is not registered through `/v2/ans/identities`.

## 1. Identifier form, canonicalization, selection

- **Form**: a DNS hostname — the agent's `agentHost` (e.g. `agent.example.com`).
- **Canonicalization**: lowercase; IDNA/punycode A-label form; no trailing dot. The version
  prefix (`v1.0.0.`) lives only in the ANS-name hostname label, never in the bare FQDN.
- **Selection**: established by the agent registration itself (ANS-1), not through the identity
  API.

## 2. Control proof — both axes

`fqdn` is the one identity in this version exercising **both** axes of the gate
([ANS-0 §3.1](../ans-0-identity-anchor.md#31-the-two-axes)). The proof is the ACME-based domain
validation and certificate issuance already specified by
[ANS-3 §7 (DNS verification modes)](../ans-3-dns-publication.md#7-dns-verification-modes) and
[ANS-2 §3 (The Identity Certificate)](../ans-2-versioned-naming.md#3-the-identity-certificate);
this profile only states how it maps onto the gate. Checks, in order:

1. **Identifier control (ACME DNS-01).** The registrant provisions the `_acme-challenge.<host>`
   TXT record the ACME order names, and the CA validates control of the FQDN. This is the
   *location challenge* of [ANS-0 §3.3](../ans-0-identity-anchor.md#33-identifier-control-the-location-challenge).
2. **Key control (CSR self-signature).** The registrant submits a PKCS#10 CSR; its
   self-signature proves possession of the private key. The CA binds that key to the FQDN by
   issuing the certificate.

Both axes clean → the agent's primary anchor is proven; the registration may activate
(seal-before-success, ANS-1 §4.2). No `IdentityProofInput`/JWS round-trip applies here — the
cert binding *is* the proof.

## 3. Key source and selection

The authoritative key is the one bound to the FQDN by the issued certificate (the CSR public key
for self-signed/ACME issuance, or the leaf key for BYOC). No `kid` selector applies; there is one
key per certificate.

## 4. Seal tier

n/a as an identity seal — `fqdn` seals through the **agent** event family
([ANS-1 §6](../ans-1-registration.md#6-event-set)): the issued identity/server certificates are
carried in the `AGENT_REGISTERED`/`AGENT_RENEWED` attestations (`identityCerts[]`,
`serverCerts[]`) and the provisioned records in `dnsRecordsProvisioned[]`. The FQDN is never
sealed as an `IDENTITY_*` event and never appears on the identity read surface.

## 5. Freshness and monitoring

Freshness is the certificate lifetime plus renewal ([ANS-1 §7](../ans-1-registration.md#7-lifecycle-operations));
ANS-5 monitors the served TLS material and DNS state against the sealed attestation.

## 6. Lifecycle specifics

Rotation, renewal, and revocation of the primary anchor are the **agent** lifecycle
([ANS-1 §7](../ans-1-registration.md#7-lifecycle-operations); DNS effects per ANS-3). A linked
Verified Identity survives the agent's revocation (ANS-0 §9).

## 7. Outbound-fetch safety

The verification I/O is DNS (DNS-01) and ACME HTTP to the configured CA; no registrant-steered
fetch applies.

## 8. Error codes

Failures surface through the registration/verification flows (ANS-1/ANS-2) as RFC 7807 Problem
Details — ACME order failures, DNS-01 validation failures, CSR rejection (`IDENTITY_CSR_NOT_PERMITTED`
when a CSR is supplied on a path that does not permit it), and the certificate-management codes of
ANS-3. This profile defines no `IDENTITY_*`-surface codes of its own.

## 9. Status and requirement

**Requirement: Required.** Every agent registration is anchored to one FQDN, proven on the ANS-1 path.

**Status: Active.** This is the original, fully-implemented anchor path; the identity gate
generalizes it.

## 10. Object schemas

`fqdn` seals through the agent event family: its sealed object is the `AGENT_REGISTERED`
attestation — `identityCerts[]`, `serverCerts[]`, `dnsRecordsProvisioned[]` —
([ANS-1 §6.1](../ans-1-registration.md#61-agent_registered)). The identity-event conformance schema
[`api/identity-event-schema-v2.json`](../../api/identity-event-schema-v2.json) does **not** apply
to the primary anchor.
