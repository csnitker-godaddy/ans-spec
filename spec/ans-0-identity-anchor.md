# ANS-0: Identity

Status: DRAFT v1.0
Spec: ANS-0 (Identity)
Version: 0.2.0
Date: 2026-06-23
Audience: implementers building an ANS-conformant Registration Authority, Transparency Log, Integrity Monitor, or verifier

## 1. Scope

ANS-0 defines proof of control for agent anchors and optional Verified Identities.

- Every agent registration (ANS-1) MUST have one FQDN primary anchor: the agent's `agentHost`.
- A **Verified Identity** represents an operator or legal entity. It is owned by a `providerId`,
  proven and sealed independently, and may be linked to that owner's agents.
- The Verified Identity capability is optional. An RA without it remains conformant, exposes no
  `/v2/ans/identities` routes, and seals no `IDENTITY_*` events (§12).

This document defines the identity object, lifecycle, links, and identity API/TL surfaces (§§4–8),
the agent-anchor relationship (§9), and identity profiles (§10). Per-kind proofs are defined in
[identity-profiles/](identity-profiles/). Agent registration is defined in [ANS-1](ans-1-registration.md),
log proofs in [ANS-4](ans-4-transparency.md), and monitoring in [ANS-5](ans-5-integrity-monitoring.md).
Trust scoring is outside ANS.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are interpreted as in RFC 2119.

## 2. Terminology

- **Identifier** — a public, stable string an operator controls: an FQDN, a DID, an LEI.
- **Identity** — a *control-proven* identifier. ANS holds two identity shapes: the agent's
  primary anchor (the what) and a Verified Identity (the who).
- **Verified Identity** — the owner-scoped object of §4, proven through a control proof and sealed on
  its own TL stream.
- **Identity profile** — a separate document under [`identity-profiles/`](identity-profiles/)
  that defines how one identifier **kind** (`did:web`, `did:key`, `lei`, `fqdn`, …) is selected,
  control-proven, validated, sealed, and monitored.
- **Kind** — the profile selector carried on an identity; the set is closed (§10).
- **Control proof** — the cryptographic evidence the registrant presents to prove control of an
  identifier.
- **Proven key** — a verification method whose possession the registrant demonstrated and which
  the RA therefore sealed. An identity may have several (§3.2 multi-key).
- **Identity link** — an owner-gated association binding a Verified Identity to one of that
  owner's agents (§6). A link is a sealed fact, not a cryptographic operation.

## 3. The proof-of-control gate

The applicable identifier-control and key-control proofs MUST succeed before an identity is sealed.

### 3.1 The two axes

Every identity seals only after **both** applicable axes pass:

| Axis | Question | FQDN primary (the what) | Verified Identity (the who) |
| --- | --- | --- | --- |
| **Identifier control** | "Can you act as the controller of this identifier?" | ACME DNS-01 (`_acme-challenge` TXT) | A *location challenge* — only for kinds with a writable location. No kind in this version's Verified-Identity set has one (§9, profiles). |
| **Key control** | "Do you hold the key you will sign as?" | CSR self-signature, bound to the FQDN by the issued certificate | A *challenge-bound signature* over the canonical proof input (§3.2). |

Each profile defines its applicable axes (§10).

### 3.2 Key control — a challenge-bound proof of key possession

1. On register / rotate (`PUT`), the RA issues a random, expiring, single-use `nonce` bound to
   this identity and this operation, and returns the **list of challenges to sign**.
2. The registrant signs the **served signing input**. There is exactly **one** signing input in
   the system: the RFC 8785 (JCS) canonical bytes of **`IdentityProofInput`**, base64url-encoded:

   ```json
   {
     "identifier": "<canonical identifier>",
     "identityId": "<uuid>",
     "nonce": "<issued nonce>",
     "purpose": "ans:identity-proof:v1",
     "raId": "<ra id>",
     "scheme": "<kind, e.g. did:web | did:key | lei>"
   }
   ```

   - **`purpose`** is the fixed domain separator `ans:identity-proof:v1`, preventing reuse of a
     signature from another protocol as an ANS control proof.
   - **`raId`** is the RA's configured external base URL, identical for every registrant in that
     deployment and **never derived from request headers**. It prevents cross-RA proof reuse.
   - **The RA serves the signing input; clients never canonicalize.** The register/rotate `202`
     carries `challenges[].signingInput` = the base64url of the exact JCS bytes. For JWS schemes
     the compact JWS's **payload segment MUST equal that string verbatim** (the RA checks
     payload-equality *before* verifying any signature); for non-JOSE schemes (lei CESR) the
     signed message is the decoded bytes.
3. The RA verifies the proof(s) against the **authoritatively resolved** key(s), with `alg`
   pinned to the resolved key type (alg-confusion defense), and confirms the `nonce` is unexpired
   and unconsumed. A nonce MUST authorize **at most one** successful verify-control operation,
   including under concurrent requests and recovery from interrupted attempts. The successful
   identity transition and consumption of its nonce MUST be one indivisible RA outcome; an
   unsuccessful attempt MUST NOT itself consume the nonce or apply the transition. Success means
   the authorized transition commits, whether or not the caller receives the response.

The verifying key MUST come from the identifier's authoritative source, as defined by its profile.
The protected JWS `kid` selects within that identity's resolved key set; it MUST NOT redirect
resolution to another identifier. The signature algorithm is bound to the resolved key type.

**Multiple keys.** When the identifier authoritatively publishes several keys (`did:web`, and the
deferred `did:plc`/`did:ion`), the registrant MAY prove possession of more than one by submitting
**one JWS per key** (`signedProofs[]`), each the *same* `IdentityProofInput` signed under a
different key, each header naming that key's `kid`. The RA verifies **every** submitted proof
(one bad proof fails the call closed) and **seals every key that verifies** as its own proven key
(§8), against the **one** shared nonce, consumed once. `did:key` and `lei` are single-key.

**Token discipline.** The `nonce` is single-use and bound to the identity and operation it was
issued for; default TTL 1 hour (configurable; high-assurance deployments SHOULD configure a
materially shorter window, on the order of minutes). A failed attempt does not consume the nonce.
After expiry, recovery is the idempotent re-add (§5) on the same `identityId`.

### 3.3 Identifier control: the location challenge

The FQDN primary's identifier-control challenge is the ACME DNS-01 flow on the agent-registration
path ([fqdn profile](identity-profiles/fqdn.md)). This version defines no generic location challenge.

### 3.4 Seal the proof, not the claim

The RA MUST NOT emit an attestation naming an identifier until key control (and, for the FQDN
primary, identifier control) has returned clean. The sealed attestation records *that control was
proven, of which keys, by what method, when*.

## 4. The Verified Identity object

A Verified Identity is owned by a `providerId` and is independent of any agent.

```typescript
interface VerifiedIdentity {
  identityId: string;     // UUIDv7, RA-assigned
  providerId: string;     // owner — the same authentication principal as the owner's agents
  kind: string;           // profile selector: "did:web" | "did:key" | "lei" | …
  value: string;          // canonical identifier (profile-normalized)
  status: "PENDING_CONTROL" | "VERIFIED" | "REVOKED";
  proofMethod: string;    // e.g. "did-web-sig" | "did-key-sig" | "lei-vlei-acdc"
  verifiedAt?: string;    // RFC 3339 UTC, set when status becomes VERIFIED
}
```

The Verified Identity object carries no key-material field; its sealed TL events (§8) are the
authoritative record of its proven keys. Keys reported for a `VERIFIED` identity are quoted from its
current sealed proof event with `keysLogId`; a `REVOKED` identity's current view omits `keys[]`; a
view that cannot be computed follows its surface's unavailable result (§8.2).

An identity with **zero** linked agents is valid.

## 5. Identity lifecycle

```text
[*] --> PENDING_CONTROL          register (202 + challenges)
PENDING_CONTROL --> PENDING_CONTROL   re-add same value (idempotent, fresh nonce)
PENDING_CONTROL --> VERIFIED     verify-control clean → seal IDENTITY_VERIFIED
VERIFIED --> VERIFIED            PUT + verify-control → seal IDENTITY_UPDATED (rotation)
VERIFIED --> REVOKED             POST …/revoke → seal IDENTITY_REVOKED
REVOKED  --> [*]                 terminal
```

1. **Register** — `POST /v2/ans/identities {value}`. The RA infers the kind from lexical form
   (§10), canonicalizes it, runs the profile's advisory resolution to seed the challenge list,
   creates the identity in `PENDING_CONTROL` under the caller's `providerId`, and returns `202` with
   the challenges to sign. **Idempotent re-add:** while the identity is `PENDING_CONTROL`, the same owner
   re-`POST`ing the same value gets `202` with the **same `identityId`** and a fresh nonce.
   `IDENTIFIER_DUPLICATE` is reserved for genuine conflicts: already `VERIFIED` by this owner
   (rotate instead), or proven by another owner (§11 uniqueness).
2. **Verify-control** — `POST /v2/ans/identities/{identityId}/verify-control` with the proof(s)
   over `IdentityProofInput` (§3.2). Clean → `VERIFIED`, seal `IDENTITY_VERIFIED`.
3. **Rotate / replace** — `PUT /v2/ans/identities/{identityId} {value}` stages a same-kind
   replacement and returns fresh challenges. The previously sealed state **stands** until the new
   proof lands (the identity remains `VERIFIED` with the replacement staged); a replacement that never
   verifies expires with its nonce. A clean verify-control seals `IDENTITY_UPDATED` — **one
   event, regardless of how many agents are linked** (§8 fan-out). Cross-kind replacement is
   rejected (remove + add, not a rotation).
4. **Revoke** — `POST /v2/ans/identities/{identityId}/revoke` → `REVOKED`, seal
   `IDENTITY_REVOKED`.

### 5.1 Seal-before-success (normative)

No identity operation reports success before its event is sealed. Verify-control, `PUT`, revoke,
link, and unlink return success **only after the TL acknowledges the seal**, and the identity's
state transition (and nonce consumption) takes effect with that acknowledgment. If the TL is
unavailable the operation fails retryable (`503 TL_UNAVAILABLE`), the nonce is **not** consumed,
and the prior state stands. If the TL *rejects* the event (a producer-side bug), the operation
fails (`502 TL_REJECTED_EVENT`).

This mirrors the rule ANS-1 §4.2 applies to agent activation (an agent MUST NOT activate without
a sealed event). While a verify-control attempt is in flight for a nonce — between passing its
proof checks and receiving its seal acknowledgment — a competing attempt on the same nonce MUST
receive `409 VERIFICATION_IN_FLIGHT` and MUST NOT consume the nonce. An interrupted attempt MUST
NOT exclude retries indefinitely: the exclusion expires within approximately 30 seconds, as the
API specifies. Recovery or expiry of that exclusion MUST NOT allow a delayed attempt to commit
after another attempt has consumed the nonce. Revoke, link, and unlink MUST take effect only
while their required state and ownership conditions still hold; an operation that loses a race
fails with its gate's error rather than overwriting a concurrent committed transition.

## 6. Identity links

A link binds a Verified Identity to one of its owner's agents. Cross-owner links are not permitted.

**Authorization.** The caller MUST own both the identity and every named agent: each `providerId`
MUST equal the authenticated principal. Key possession alone never authorizes a link. Routine
link, unlink, and revoke operations do not require an identity-key signature; the identity key
proves control during verification and rotation.

**Liveness.** The identity MUST be `VERIFIED`, and each agent MUST have registration status `ACTIVE`
or `DEPRECATED`. Terminal and pre-activation agents are rejected with `AGENT_NOT_LINKABLE`.
This gate uses registration status; `WARNING` and `EXPIRED` derived by the TL are badge states.
The current-view visibility predicate additionally treats `WARNING` as live (§8.2).

**Residual risk.** Stolen owner credentials can authorize a link between the victim's identity and
an attacker-controlled agent registered under that account. Deployments MAY require step-up
authentication on link/unlink/revoke. The link route enforces deployment-configured per-owner rate
limits and per-call `agentIds[]` cardinality caps.

**Events.** One owner-gated batch call seals exactly one `IDENTITY_LINKED` event whose `ansIds[]`
contains exactly the submitted `agentIds[]` (§7). Unlink (`DELETE …/links/{agentId}`) seals
`IDENTITY_UNLINKED`, ends the association, and preserves its sealed history. Current views MUST
exclude the association until a later authorized `IDENTITY_LINKED` re-establishes it. Deleting or
rebuilding internal state MUST NOT resurrect an earlier link or discard its sealed history.

## 7. API surface

The identity object is managed through the V2 RA API. The route table:

```text
POST   /v2/ans/identities                              register → 202 + challenges to sign
GET    /v2/ans/identities                              list (mine) — paginated
GET    /v2/ans/identities/{identityId}                 detail (status, live links)
PUT    /v2/ans/identities/{identityId}                 rotate / replace → 202 + fresh challenges
POST   /v2/ans/identities/{identityId}/verify-control  proof → seal IDENTITY_VERIFIED | IDENTITY_UPDATED
POST   /v2/ans/identities/{identityId}/revoke          state change → seal IDENTITY_REVOKED (not DELETE)
POST   /v2/ans/identities/{identityId}/links           {agentIds[]} → seal ONE IDENTITY_LINKED (200)
DELETE /v2/ans/identities/{identityId}/links/{agentId} unlink → seal IDENTITY_UNLINKED
```

Every route is owner-scoped: the caller's `providerId` MUST own the identity, and link routes
additionally require owning the agent (§6). A read for an identity the caller does not own returns
404 (existence hidden); a write returns 403. A kind with no enabled profile returns
`422 IDENTIFIER_KIND_UNSUPPORTED` — no placeholder seal.

Wire bodies are defined in [`api/api-spec-v2.yaml`](../api/api-spec-v2.yaml); the `lei` and `ens`
request shapes are in their profiles.

The agent detail/list responses (ANS-1) additionally carry a **computed**, optional
`identities[]` array — the RA-side current-links view, derived from the sealed link events and
never a sealed property of the registration. It is
the common-core subset (`identityId, kind, value, identityStatus, linkedAt`) of the TL badge
entry (§8).

## 8. Transparency-Log surface

Identity events are appended to the single ANS-4 log; a "stream" is the read view selected by
`identityId` or `ansId` ([ANS-4 §5.3](ans-4-transparency.md#53-identity-surface)).

### 8.1 The identity event family and ingest

ANS-0 adds five V2 event types, all served on the identity stream:

```text
IDENTITY_VERIFIED   first proof — carries the full proven key set
IDENTITY_UPDATED    rotation — proven key set replaced (carries previousValue)
IDENTITY_REVOKED    state change
IDENTITY_LINKED     batch link — carries ansIds[]
IDENTITY_UNLINKED   unlink — carries ansIds[]
```

Identity events are ingested at `POST /v1/internal/identities/event`; cross-lane bodies are rejected
`422 INVALID_EVENT` ([ANS-4 §6](ans-4-transparency.md#6-producer-authentication)). Proofs,
rotations, and revocations are served on the identity's stream; link events are additionally served
through each named agent's identity-history endpoint (`GET /v1/agents/{agentId}/identities/history`),
never as events in that agent's lifecycle audit.

**An identity operation never appends to an agent's event or audit history**, and vice versa.

**Sealed payload (the append-only contract).** The producer-authored inner event — JCS-canonical
before signing, keyed by `identityId` — carries:

| Field | Type | Present on |
| --- | --- | --- |
| `eventType` | enum (the five tokens above) | every event |
| `identityId` | string (UUIDv7, the stream key) | every event |
| `kind` | enum `did:web` \| `did:key` \| `lei` \| `ens` | every event |
| `value` | string (canonical identifier) | every event |
| `timestamp` | string (RFC 3339) | every event |
| `keys[]` | array of `ProvenKey` | `IDENTITY_VERIFIED`, `IDENTITY_UPDATED` (required, non-empty) |
| `verifiedAt` | string (RFC 3339) | `IDENTITY_VERIFIED`, `IDENTITY_UPDATED` (required) |
| `providerId` | string (the who's owner) | `IDENTITY_VERIFIED`, `IDENTITY_UPDATED` (required) |
| `proofMethod` | enum `did-web-sig` \| `did-key-sig` \| `lei-vlei-acdc` \| `ens-account-sig` | proof events |
| `previousValue` | string (pre-rotation identifier) | `IDENTITY_UPDATED` |
| `revokedAt` | string (RFC 3339) | `IDENTITY_REVOKED` (required) |
| `ansIds[]` | array of agent ids (the whole batch) | `IDENTITY_LINKED`, `IDENTITY_UNLINKED` (required, non-empty); absent on every other event type |
| `raId` | string | optional, all |

A **`ProvenKey`** is `{verificationMethod, signedProof}`: the `verificationMethod` is the source's
object quoted verbatim (§8.4), and `signedProof` is the registrant's compact JWS over the served
`IdentityProofInput` (the `lei` thumbprint-only variant is the documented exception — see the lei
profile). See the [ANS-4 envelope example](examples/ans-4-examples.md#a1-sealed-envelope-and-append-response)
and [did:web proof/key example](identity-profiles/did-web.md#10-object-schemas-worked-example).

The machine-readable conformance schema for this payload — the closed `eventType` set, the field
set, and the per-type required-field matrix encoded as JSON Schema (draft-07) `if`/`then` — is
[`api/identity-event-schema-v2.json`](../api/identity-event-schema-v2.json). A sealed identity log
entry MUST validate against it.

### 8.2 Computed reads and the visibility predicate

Higher-spec views that show "who is behind this agent" MUST reflect the sealed identity and link
events under the visibility predicate below and the terminality rule of §8.3. A rotation or
revocation MUST become visible on every linked agent's current view once sealed, while producing
exactly one identity event regardless of the number of linked agents.
Implementations MAY precompute or cache these views only if every response satisfies the same
visibility and terminal-revocation rules; this introduces no staleness allowance. The V2 badge's
computed `status` follows the same rule.

A link is **visible** in a "current" view when the link's latest event is `LINKED` **and** the
agent is **live** — `ACTIVE`, `DEPRECATED`, or `WARNING` (not terminal). Within a visible entry,
the identity's own status is reported as-is:

- A `VERIFIED` identity carries its current proven `keys[]` (verbatim verification methods, §8.4)
  and `keysLogId` — the `logId` of the `IDENTITY_VERIFIED`/`IDENTITY_UPDATED` seal those keys are
  quoted from.
- A `REVOKED` identity **stays listed** with `identityStatus: REVOKED` and `keys[]` omitted — a
  verifier looking at a still-linked agent MUST see that the who was revoked, not have it
  silently vanish. Only an unlink removes the entry.

When the join cannot be computed, the badge omits `identities[]` and sets
`identitiesUnavailable: true` — an empty array always means "no visible links", never "the join
failed".

The identity read surface (TL):

```text
GET /v1/identities/{identityId}            latest sealed event + proof + computed {status, keys[], keysLogId}
GET /v1/identities/{identityId}/audit      the identity's full event chain (standard audit envelope)
GET /v1/identities/{identityId}/receipt    SCITT COSE receipt for the identity leaf
GET /v1/identities/{identityId}/agents     reverse join — currently-linked agents (paginated)
GET /v1/agents/{agentId}                   agent badge — gains the computed identities[] join
GET /v1/agents/{agentId}/identities        the computed list, served alone (paginated)
GET /v1/agents/{agentId}/identities/history the link/unlink events naming this agent (audit envelope)
```

### 8.3 Read-side revocation terminality

Identity status on a "current" view is derived from the rule **REVOKED iff any `IDENTITY_REVOKED`
exists on the stream** — not merely when it is the stream tail. Seal-before-success spans a
network round trip, so a racing operation's event can land *after* a revocation leaf; a late leaf
MUST NOT flip a revoked identity's public answer back to `VERIFIED`.

### 8.4 Seal-verbatim rule

Each proven key is sealed as the **verification method exactly as the identifier published it** —
`id`, `type`, `controller`, and the key material in whichever representation the source used
(`publicKeyJwk`, or `publicKeyMultibase` for Multikey documents) — copied member-for-member,
values untouched, alongside the signed challenge. **No derived values are sealed**: no
thumbprints, no re-encodings, no normalization. A third-party verifier checks operator signatures
from the badge alone (byte-recompute the `IdentityProofInput`, verify the JWS against the sealed
method, reject unrecognized `crit` headers per RFC 7515 §4.1.11). The profile names which
representation it seals; `lei` seals thumbprint-only (see the [lei profile](identity-profiles/lei.md)
§4).

## 9. The who, the what, and the FQDN primary anchor

An agent's mandatory FQDN primary anchor is its `agentHost`, proven through the
[fqdn profile](identity-profiles/fqdn.md) on the ANS-1 registration path. It is not a Verified
Identity and is not addressable through the identity API.

**Independent lifecycles.** An agent's revocation emits no identity event and does not remove its
operator's Verified Identity or sealed history. An identity's revocation emits no agent event.
The owner may link an existing Verified Identity to a successor agent; link visibility follows
the sealed state of both objects (§8.2).

## 10. Identity profiles

Each identifier kind has a document under [identity-profiles/](identity-profiles/) defining its
selection, proof, validation, sealing, and monitoring rules. Adding or retiring a kind requires
an ANS-0 amendment to the registry and its closed `kind` / `proofMethod` sets (§10.3).

### 10.1 The profile registry

| Kind | Profile | Requirement | Axes | Seal tier | Status |
| --- | --- | --- | --- | --- | --- |
| `fqdn` (agent primary) | [fqdn](identity-profiles/fqdn.md) | Required | identifier (ACME) + key (CSR) | n/a (cert-bound) | Active |
| `did:web` | [did-web](identity-profiles/did-web.md) | Optional | key only (multi-key) | verbatim verification method | Active |
| `did:key` | [did-key](identity-profiles/did-key.md) | Optional | key only | verbatim verification method (derived Multikey) | Active |
| `lei` | [lei](identity-profiles/lei.md) | Optional | key only (vLEI-validated) | thumbprint-only (AID + key thumbprint) | Postponed |
| `did:plc` | [did-plc](identity-profiles/did-plc.md) | Optional | key only (multi-key) | verbatim verification method | Deferred (sketch) |
| `did:ethr` / `did:pkh` | [did-ethr](identity-profiles/did-ethr.md) | Optional | key only (EIP-712 / ERC-1271) | verbatim verification method | Deferred (sketch) |
| `did:ion` | [did-ion](identity-profiles/did-ion.md) | Optional | key only (multi-key) | verbatim verification method | Deferred (sketch) |
| `ens` | [ens](identity-profiles/ens.md) | Optional | key only (EIP-712 / ERC-1271, name-owner signature) | verbatim verification method | Postponed |

> `fqdn` is the agent's primary anchor on the ANS-1 registration path, not a
> `/v2/ans/identities` dispatch kind.

**Requirement.** `fqdn` is required for every agent registration. Every other row is optional to
adopt; once an RA enables a kind, that profile's checks are mandatory.

**Status** is orthogonal to requirement and describes implementation maturity. A profile marked
**Active** is implemented, tested, and sealing real proofs. **Postponed** means the flow is the design
of record and de-risked but disabled until its external plumbing is enabled (the kind returns
`IDENTIFIER_KIND_UNSUPPORTED`). **Deferred (sketch)** documents the intended shape only; it ships
when its resolver, tests, and external plumbing are real (per the "404 is the signal" rule — an
unimplemented kind is unregistered, not a placeholder).

### 10.2 What a profile MUST define

Every profile document MUST specify the following content:

1. **Identifier form and canonicalization**, and **how the kind is selected** — lexical dispatch
   (a prefix/shape the RA recognizes) or explicit-kind registration (for kinds not safely
   lexically distinguishable).
2. **Control proof** — which axes apply and the exact `verify-control` checks, **in order**
   ("passes" = every listed check clean; the seal happens only then).
3. **Key source** — where the authoritative key(s) are resolved/decoded/presented from, and the
   `kid`/key-selection rules.
4. **Seal tier** — verbatim verification method, or thumbprint-only, and exactly what is sealed
   (§8.4).
5. **Freshness and monitoring** — the ANS-5 re-check cadence and the integrity signal.
6. **Lifecycle specifics** — rotation, revocation, re-proof, anything kind-specific.
7. **Outbound-fetch safety** — for fetch-based kinds, the SSRF/egress controls.
8. **Error codes** — the kind's typed failures.
9. **Status and requirement** — Active / Postponed / Deferred, and Required or Optional.
10. **Object schemas** — worked request / challenge / seal examples (Active and Postponed profiles).

### 10.3 Adding or changing a kind

A new kind is added by writing a profile document and adding a row to the §10.1 registry table —
an ANS-0 amendment. The core sections (§3–§9) do not change. Generic control failures use the
`IDENTIFIER_*` / `PRICC_*` codes defined here; kind-specific failures use the scheme-prefixed
codes the profile defines (`FQDN_*`, `DID_*`, `LEI_*`, `ENS_*`). The `PRICC_*` family
(`PRICC_SIGNATURE_INVALID`, `PRICC_TOKEN_EXPIRED`, `PRICC_TOKEN_ALREADY_USED`) names §3.2
proof-of-control failures shared by every key-control profile (PriCC: Private-key Confirmation
Challenge).

The kind set is frozen by specification: every `kind` and `proofMethod` value a conformant RA emits
MUST belong to the set defined here, and the RA MUST reject unsupported kinds with
`IDENTIFIER_KIND_UNSUPPORTED`.

## 11. Cross-identity equivalence

An owner expresses a shared operator identity by linking one Verified Identity to its agents
(§6). The link is the equivalence assertion; no separate equivalence event is defined.

**Uniqueness.** One `(kind, value)` is `VERIFIED` by at most one owner across an RA; a later proof of
a value another owner holds fails `IDENTIFIER_DUPLICATE`. An unproven `PENDING_CONTROL` identity
cannot squat a value.

**Compromise does not silently cascade.** Revoking an identity revokes neither its linked agents nor
any other identity (§9); ANS-5 surfaces an identity revoked while a linked agent still claims it as a
finding.

## 12. Conformance

Conformance is split: a small mandatory core every RA meets, and the optional Verified Identity
capability, which an RA that implements it MUST implement exactly as specified.

### 12.1 Mandatory core

Every ANS-0 conformant RA proves the agent's FQDN primary anchor through the proof-of-control gate
(§3, [fqdn profile](identity-profiles/fqdn.md)) and emits a typed error (with a documented code) on
any failure.

### 12.2 Optional capability: Verified Identities

An RA **MAY** implement the Verified Identity surface. An RA that does MUST implement §§3–11 as
written.

### 12.3 Verifier

A conformant **verifier** reconstructs and checks proofs from sealed events alone (§8.4), and
treats a `REVOKED` identity as revoked regardless of any later stream entry (§8.3).

## 13. Security considerations

- **Outbound-fetch (SSRF).** Fetch-based profiles (`did:web`, future `did:plc`/`did:ion`) make
  server-side requests to registrant-steered hosts. Every connection attempt such a fetch makes —
  including redirects, alternate address attempts, and reconnections — MUST use an actual
  destination address outside the egress denylist (RFC 1918, loopback, link-local incl. cloud
  metadata, ULA), evaluated against the address actually used after DNS resolution; a hostname
  check, or validation followed by an unchecked second resolution, is insufficient, and a DNS
  change during the operation MUST NOT permit a connection to a prohibited destination. Every
  fetch MUST satisfy full WebPKI validation, a bounded timeout and response size, and caller-visible
  errors MUST NOT disclose resolved IPs, ports, or redirect chains (no SSRF oracle) while remaining
  diagnosable to the RA's operators. The profile specifies the particulars.

## 14. References

- Identity profiles: [`identity-profiles/`](identity-profiles/) (fqdn, did-web, did-key, lei,
  ens, and deferred sketches).
- [ANS-1: Registration & Lifecycle](ans-1-registration.md) — the agent (the what) and the event
  set.
- [ANS-4: Transparency](ans-4-transparency.md) — the single Merkle log, identity ingest and read
  surface, SCITT receipts.
- [ANS-5: Integrity Monitoring](ans-5-integrity-monitoring.md) — per-identity monitoring.
- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/): DID syntax, verification relationships.
- [ISO 17442](https://www.iso.org/standard/78829.html): LEI structure and checksum.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): JSON Canonicalization Scheme (JCS).
- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555): ACME.
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515): JSON Web Signature (JWS).
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517): JSON Web Key (JWK).
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119): Requirement keywords.
