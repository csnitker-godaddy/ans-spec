# ANS-1: Registration & Lifecycle

Status: DRAFT v1.0
Spec: ANS-1 (Registration & Lifecycle)
Version: 0.2.0
Date: 2026-07-02
Audience: implementers building an ANS-conformant Registration Authority (RA)

## 1. Scope

ANS-1 defines how an agent's **primary anchor** — an FQDN proven through ANS-0's [fqdn profile](identity-profiles/fqdn.md) — binds to operational metadata (display name, description, endpoints) and how that binding moves through a lifecycle. ANS-1 specifies:

- The registration operations: register, verify-acme, verify-dns, revoke, plus server-certificate renewal and identity-certificate rotation.
- The registration aggregate's data shape and identifier set.
- The lifecycle state machine (§4.4).
- The event set the RA emits to the Transparency Log (ANS-4).

The primary anchor is proven through the ANS-0 proof-of-control gate
([ANS-0 §3](ans-0-identity-anchor.md#3-the-proof-of-control-gate)) via the fqdn profile; operator
identities are Verified Identities ([ANS-0 §4](ans-0-identity-anchor.md#4-the-verified-identity-object),
[§6](ans-0-identity-anchor.md#6-identity-links)), not registration anchor types. ANS-1 does not
specify naming (ANS-2), DNS emission (ANS-3), sealing (ANS-4), or monitoring (ANS-5).

## 2. Terminology

- **Registration**: an aggregate the RA owns, identified by `agentId`, carrying the ANSName (`version` + `agentHost`), operational metadata, status, and lifecycle history.
- **AHP (Agent Hosting Platform)**: the operator that hosts the agent's code and manages its DNS and certificates. Submits the registration request.
- **Lifecycle event**: an event the RA emits to the TL when a registration changes state.
- **Identity Certificate**: an optional certificate binding the registration's ANSName, issued from the RA's private CA against an operator-submitted CSR.

## 3. Registration operations and lifecycle

The RA MUST expose the registration, verification, retrieval, listing, revocation, Server Certificate
renewal, and Identity Certificate rotation operations defined by this specification and the RA API.
The listing operation is owner-scoped and supports `agentHost` filtering.
It MUST honor the lifecycle statuses `PENDING_VALIDATION`, `PENDING_DNS`, `ACTIVE`, `DEPRECATED`,
`REVOKED`, `FAILED`, and `EXPIRED`, and the transitions in §4.4. While certificate issuance is in
progress, the pending-registration response MUST expose the `PENDING_CERTS` phase; this is not an
additional lifecycle status or list-filter value.

The `agentHost` field is the agent's operational FQDN: ANS-3 (DNS publication) consumes it for record generation, and together with `version` it derives the registration's ANSName.

## 4. Registration sequence

Registration is a three-step flow driven by the AHP: the RA accepts the request and returns the domain-control
challenges (`PENDING_VALIDATION`), verify-acme proves domain control and issues certificates (`PENDING_DNS`),
and verify-dns confirms the published records and activates the agent (`ACTIVE`).

### 4.1 Step 1 — pending registration

The AHP submits a registration request:

| Group | Field | Required | Description |
| --- | --- | --- | --- |
| **Identity** | `agentHost` | Yes | Operational FQDN (RFC 1123) |
| | `version` | Yes | Semantic version, bare semver (e.g., `1.0.0`) |
| | `agentDisplayName` | Yes | Human-readable name (max 64 chars) |
| | `agentDescription` | No | Brief capability description (max 150 chars) |
| **Endpoints** | per-endpoint `protocol` | Yes | `A2A`, `MCP`, or `HTTP_API` (minimum 1 endpoint) |
| | per-endpoint `agentUrl` | Yes | The endpoint URL; its hostname MUST equal `agentHost` (case-insensitive) |
| | per-endpoint `metaDataUrl` | No | Protocol metadata location |
| | per-endpoint `metaDataHash` | No | `SHA256:`-prefixed SHA-256 of the document at `metaDataUrl`, computed and declared by the AHP (format-validated by the RA, not re-fetched). Sealed into the TL `attestations.metadataHashes` map keyed by the protocol token |
| | per-endpoint `documentationUrl` | No | Developer documentation |
| | per-endpoint `functions` | No | Function declarations: `id`, `name`, optional `tags` |
| | per-endpoint `transports` | No | `STREAMABLE_HTTP`, `SSE`, `JSON_RPC`, `GRPC`, `REST`, `HTTP` |
| **Discovery** | `discoveryProfiles` | No | The DNS record families the RA emits for this registration, per [ANS-3 §6](ans-3-dns-publication.md#6-discovery-profiles). Defaults to `ANS_DNSAID` |
| **Certificates** | `identityCsrPEM` | No | CSR for the Identity Certificate. When omitted, the agent registers without one and cannot add one later (§7.2) |
| | `serverCsrPEM` | Conditional | CSR for the RA-issued Server Certificate |
| | `serverCertificatePEM` (+ optional `serverCertificateChainPEM`) | Conditional | BYOC Server Certificate. Exactly one of `serverCsrPEM` / `serverCertificatePEM` MUST be present |

Pending-stage validations:

1. `agentHost` MUST be a syntactically valid FQDN (RFC 1123).
2. Each endpoint's `agentUrl` MUST carry `agentHost` as its hostname (case-insensitive).
3. Exactly one of `serverCsrPEM` and `serverCertificatePEM` MUST be present.
4. The endpoint set MUST contain at least one endpoint with valid `protocol` and `agentUrl`, and at most one endpoint per protocol (`DUPLICATE_PROTOCOL`, 422).
5. `agentDisplayName` and `agentDescription` length limits apply (64 and 150 chars respectively).
6. The ANSName derived from `version` + `agentHost` MUST be globally unique; a taken name is rejected with `ANS_NAME_TAKEN` (409).

If valid, the RA assigns an `agentId` (UUID v4), constructs the ANSName per [ANS-2 §2](ans-2-versioned-naming.md), opens a certificate order at the configured server-certificate issuer, and sets the registration to `PENDING_VALIDATION`. The response relays the order's domain-control challenges (DNS-01 TXT and/or HTTP-01) verbatim to the AHP.

### 4.2 Step 2 — verify-acme (domain control and certificate issuance)

After publishing a challenge artifact, the AHP calls `verifyACME(agentId)`. The challenge gate passes when either the DNS-01 TXT record or the HTTP-01 resource verifies. The gate is unconditional — it runs on every registration.

On a passing gate the RA:

1. Finalizes the server-certificate order (or validates the BYOC certificate). Asynchronous CAs (e.g. RFC 8555 ACME CAs) may return an order-pending result; re-POSTing verify-acme re-drives the order until the certificate issues.
2. Signs the Identity CSR at the private CA — **only when one was submitted at registration**. A registration without a pending Identity CSR is not an error; the agent advances without an Identity Certificate.
3. Transitions the registration to `PENDING_DNS`. The verify-acme response is a status body (status, phase, completed/pending steps, timestamps); the AHP fetches the production DNS record set it must publish from the registration detail response while `PENDING_DNS` (content per [ANS-3 §3](ans-3-dns-publication.md)), and the issued certificates from the `GET …/certificates/*` endpoints.

### 4.3 Step 3 — verify-dns (activation)

After publishing the production records, the AHP calls `verifyDNS(agentId)`. The RA queries the records live; a DNSSEC-authenticated mismatch blocks activation.

When the records verify, the RA MUST transition the registration to `ACTIVE` and durably commit its
corresponding `AGENT_REGISTERED` event for delivery as one logical outcome. Failure, restart, or
concurrent requests MUST NOT leave a committed activation without its deliverable event, or deliver
an activation event for an activation that did not commit. The payload and producer signature MUST
remain byte-identical across delivery attempts. Delivery MUST be retried until accepted by the TL,
subject to producer-key validity and revocation rules. TL unavailability MAY defer delivery without
preventing local activation once this durable obligation is committed. Duplicate submissions return
the existing leaf under [ANS-4 §4](ans-4-transparency.md#4-transparency-log-operations).

### 4.4 The state machine

```text
                ┌────────────────────┐
                │ PENDING_VALIDATION │──────────────┐
                └──────────┬─────────┘              │
                           │ domain control proven, │ lapses to EXPIRED /
                           │ certificates issued    │ cancel to REVOKED
                           ▼                        ▼
                    ┌──────────────┐         ┌───────────────────┐
                    │ PENDING_DNS  │────────▶│ EXPIRED / REVOKED │
                    └──────┬───────┘         └───────────────────┘
                           │ published records verified
                           ▼
                    ┌──────────────┐         ┌──────────────┐
                    │    ACTIVE    │────────▶│  DEPRECATED  │
                    └──────┬───────┘         └──────┬───────┘
                           │ AHP or RA              │ AHP or RA
                           │ revokes                │ revokes
                           ▼                        ▼
                    ┌──────────────────────────────────────────┐
                    │                 REVOKED                  │
                    └──────────────────────────────────────────┘
```

`REVOKED`, `FAILED`, and `EXPIRED` are terminal. Revocation is idempotent. Cancelling a pending
registration transitions it to `REVOKED` without a TL event (no log entry exists for an agent that never
reached `ACTIVE`), revoking any already-issued Identity Certificates at the private CA — except a
`PENDING_VALIDATION` registration still awaiting its domain-control challenge, which is refused
(`CANNOT_CANCEL`) and lapses to `EXPIRED` on its own; pre-activation expiry likewise emits no TL
event.

TL events fire only on the `ACTIVE` and `REVOKED` transitions. Everything before activation is RA-internal.

## 5. Identifiers

| Identifier | Format | Assigned by | Mutable | Scope | Purpose |
| --- | --- | --- | --- | --- | --- |
| **`agentId`** | UUID v4 | RA at registration | No | Issuing RA | Registration-instance key; used in the RA API paths (`/v2/ans/agents/{agentId}`, `/v1/agents/{agentId}`) |
| **`ansId`** | UUID | RA | No | Issuing RA | Carried in every sealed TL event payload. In the reference implementation it is the same value as `agentId` |
| **`logId`** | UUID v7 | TL at ingest | No | TL | The Transparency Log entry identifier, wrapped around the producer event when the TL seals it |
| **`agentHost`** | RFC 1123 FQDN | AHP submits | No | Global | Operational endpoint where the agent terminates TLS |
| **`ANSName`** | `ans://v{ver}.{host}` | Derived from `version` + `agentHost` | No | Global | Versioned identifier (see [ANS-2 §2](ans-2-versioned-naming.md)); globally unique per registration |
| **`ownerId`** | RA-defined | RA from its authentication system | No | Issuing RA | The authenticated principal that owns the registration; scopes reads and lifecycle operations |

The TL wire envelopes carry an optional `providerId` field on agent events, but the agent lane leaves it empty; `providerId` is populated on identity-lane events only ([ANS-0 §4](ans-0-identity-anchor.md#4-the-verified-identity-object)).

## 6. Event set

The RA emits the following events to the ANS-4 Transparency Log. Each event carries the RA instance ID (`raId`) and the RA's producer signature, and is sealed by the TL before becoming visible to consumers.

### 6.1 `AGENT_REGISTERED`

Emitted at activation (the verify-dns transition to `ACTIVE`). Payload follows the **V2 TL format**: `ansId`
(the RA-assigned agent id), `ansName`, a nested `agent` object (`host`, `name`, `version`), `attestations` —
`identityCerts[]` (when the registration carries Identity Certificates) and `serverCerts[]`, each entry
`{fingerprint, type, notAfter}`; `dnsRecordsProvisioned[]` as `{name, type, data}` records, each optionally
carrying `dnssecVerified: true` when the verifying resolver returned the DNSSEC Authenticated-Data bit;
`domainValidation` (the constant `ACME-DNS-01`); an optional `metadataHashes` map
keyed by protocol token — plus `expiresAt` (the minimum of the latest `notAfter` in each required
certificate group, calculated under [§7.3](#73-expiry)), `issuedAt`, `raId`, and `timestamp`.

Registrations driven through the V1 paths (`/v1/agents/*`) seal **V1-format** payloads instead: a map-typed
`dnsRecordsProvisioned` with no `dnssecVerified`, and `validIdentityCerts[]` / `validServerCerts[]`
rotation arrays (the V1 agent lane remains live; identity events have no V1 lane, §6.4).

A worked example payload appears in the [ANS-1 worked examples](examples/ans-1-examples.md).

### 6.2 `AGENT_REVOKED`

Emitted when the AHP or RA revokes a registration. Payload includes `revocationReasonCode` — an RFC 5280
revocation reason name token (`KEY_COMPROMISE`, `AFFILIATION_CHANGED`, `SUPERSEDED`, `CESSATION_OF_OPERATION`,
`CERTIFICATE_HOLD`, `PRIVILEGE_WITHDRAWN`, `AA_COMPROMISE`) — and `revokedAt`. AHP submissions use the
friendlier short field name `reason`; the sealed event canonicalizes to `revocationReasonCode`.

### 6.3 Reserved event types

`AGENT_RENEWED` and `AGENT_DEPRECATED` are reserved: defined in both TL event enums, accepted at
ingest, and mapped by the TL's badge and status-token derivations (`AGENT_DEPRECATED` →
`DEPRECATED`); no operation in this version emits them.

### 6.4 Identity events (V2)

These events apply only to RAs implementing the optional
[Verified Identity capability](ans-0-identity-anchor.md#122-optional-capability-verified-identities).
RAs without that capability emit no identity events.

The `IDENTITY_*` family, its ingest lane, and the computed views on agent reads are defined in
[ANS-0 §8](ans-0-identity-anchor.md#8-transparency-log-surface); identity operations never append
to an agent's lifecycle or audit history, nor the reverse. The list response carries no identities
field.

## 7. Lifecycle operations

| Operation | Trigger | AHP submits | RA processes | RA seals | DNS effect |
| --- | --- | --- | --- | --- | --- |
| **Version bump** | Code or config change | A full new registration: new `version`, same `agentHost`, display name, endpoints, and exactly one of server CSR / BYOC (an Identity CSR MAY be included) | The new registration runs the full sequence — fresh domain-control proof, certificate issuance, DNS verification | `AGENT_REGISTERED` (for the new registration) | New per-version records published by the AHP; the prior version's records are untouched |
| **Renewal (Server Certificate)** | Certificate approaching expiration | A renewal submission (CSR or BYOC) on the renewal routes | Re-proves domain control at renewal verify-acme (DNS-01 TXT or HTTP-01), then finalizes the order and delivers the fresh certificate | Nothing (`AGENT_RENEWED` reserved — §6.3) | None |
| **Identity-certificate rotation** | Key roll on an identity-bearing registration | A fresh `identityCsrPEM` | Issues a new Identity Certificate at the private CA. Additive: the prior certificate remains valid until it expires. No fresh domain-control proof. `ACTIVE` registrations only; a registration created without an Identity CSR is refused (`IDENTITY_CSR_NOT_PERMITTED`, 409) | Nothing | AHP updates any published fingerprint records per ANS-3 |
| **Revocation** | Agent shutdown or version retirement | `reason` (RFC 5280 reason name token) | Revokes Identity Certificates at the issuing private CA (Server Certificates are not revoked at their issuer) and transitions the registration | `AGENT_REVOKED` | The revocation response lists `dnsRecordsToRemove`; the AHP removes them |

A CSR renewal whose provider order arrives with no challenges (ACME authorization reuse inside the
provider's validity window) finalizes without a fresh RA-side proof; re-driven verify-acme calls on
an already-finalizing order likewise skip the artifact check.

### 7.1 Version coexistence

Uniqueness is on the full ANSName, so versions of the same host are independent registrations with
independent statuses ([ANS-2 §2.3](ans-2-versioned-naming.md#23-supersession)); a failed new
registration leaves the old version untouched.

### 7.2 Registrations without an Identity Certificate

`identityCsrPEM` is optional. A registration created without one operates on its Server Certificate
alone and cannot add an Identity Certificate later; the path to one is a new versioned registration.

### 7.3 Expiry

The RA MUST calculate the `expiresAt` it seals in `AGENT_REGISTERED` ([§6.1](#61-agent_registered))
by taking the latest certificate expiry within each required certificate group, then the earliest
of those group expirations:

```text
serverExpiry   = max(server certificate notAfter values)
identityExpiry = max(identity certificate notAfter values)
expiresAt      = min(serverExpiry, identityExpiry)
```

`notAfter` and `expiresAt` MUST be compared by the instants they represent under RFC 3339. Different
offsets denoting the same instant MUST compare equal; textual ordering MUST NOT determine expiry.
A certificate's validity period includes its `notAfter` (RFC 5280 §4.1.2.5). A required group lapses
when the current instant is later than its latest `notAfter`.

"Latest" means the furthest `notAfter`, not the most recently issued certificate. The groups contain
every certificate in the registration's sealed `AGENT_REGISTERED` attestation, whether or not it has
since expired. Later expiry or revocation does not remove a certificate from that historical evidence
or recalculate the sealed `expiresAt`. The same calculation applies to the V1 and V2 certificate
representations.

Server Certificates are required. Identity Certificates are required for a registration that opted
into Identity Certificates; for a registration created without them ([§7.2](#72-registrations-without-an-identity-certificate)),
`expiresAt = serverExpiry`. Every required group MUST contain at least one certificate at activation.
The RA MUST NOT seal an activation attestation with a missing or empty required group, omit that group
to extend validity, or substitute an expiry for an undefined `max()`. After activation, a required
group's expiry remains the latest `notAfter` among all certificates sealed for that group, including
expired ones.

On a registration whose RA status remains `ACTIVE`, expiry of another required certificate group
MUST NOT by itself block Server Certificate renewal.
A certificate issued after activation does not update the sealed `AGENT_REGISTERED` evidence
or the `expiresAt` visible to TL consumers.

An older certificate expiring during an overlap period does not expire the registration while each
required group still has a valid replacement in the sealed evidence. The aggregate expiry does not extend
an individual certificate's validity or make a revoked certificate usable. See the [overlap example](examples/ans-1-examples.md#a4-certificate-expiry-during-overlap).

Certificate lapse MUST NOT change an `ACTIVE` registration's RA lifecycle status and emits no event;
the TL derives `WARNING` and `EXPIRED` from the sealed `expiresAt` (ANS-4). A lapsed
`PENDING_VALIDATION` registration MUST transition to `EXPIRED` without a TL event.

## 8. RA key management

| Principle | Rule |
| --- | --- |
| Agent keys | The RA never generates, handles, or accesses an agent's private keys. Registration intake is CSR- or BYOC-based; the AHP owns its key lifecycle |
| RA producer keys | Each RA instance MUST have at least one active public key registered with the ANS-4 TL before submitting events. Rotation uses an overlap window: new keys are registered with future `valid_from` dates; both old and new remain active during the transition. Producer private keys never leave the RA instance. Registration, rotation, and revocation follow [ANS-4 §6](ans-4-transparency.md#6-producer-authentication) |

## 9. Conformance

A conformant ANS-1 implementation implements §§3–8.

## 10. Security considerations

### 10.1 Reputation continuity and operator changes

Domain control is re-proven at every renewal and every new version registration (§4.2, §7), so a
party that no longer controls the domain cannot extend the registration. A failed re-proof fails
that renewal; the registration is not auto-revoked and its certificates lapse on their own
schedule, surfacing as the TL's `WARNING`/`EXPIRED` derivation.

### 10.2 Failure modes

When the TL is unavailable, agent-lane events remain durably pending and are retried byte-for-byte
(§4.3); identity-lane writes instead fail closed with `TL_UNAVAILABLE`
([ANS-0 §5.1](ans-0-identity-anchor.md#51-seal-before-success-normative)).

## References

- ANS-0 specification: [`ans-0-identity-anchor.md`](ans-0-identity-anchor.md) — the proof-of-control gate, the Verified Identity object, identity links, and the [identity profiles](identity-profiles/).
- ANS-2 specification: [`ans-2-versioned-naming.md`](ans-2-versioned-naming.md) — ANSName form, Identity Certificate binding.
- ANS-3 specification: [`ans-3-dns-publication.md`](ans-3-dns-publication.md) — DNS record emission per registration.
- ANS-4 specification: [`ans-4-transparency.md`](ans-4-transparency.md) — TL append, receipt.
- ANS-5 specification: [`ans-5-integrity-monitoring.md`](ans-5-integrity-monitoring.md) — verification results contract.
- [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123): Host requirements (FQDN syntax).
- [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339): Timestamp representation and ordering.
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280): X.509 (certificate validity and revocation reason codes).
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515): JWS (signature envelope).
- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555): ACME (FQDN domain-control proof).
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): JCS canonicalization.
