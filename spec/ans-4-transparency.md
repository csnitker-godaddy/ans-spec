# ANS-4: Transparency & Receipts

Status: DRAFT v1.0
Spec: ANS-4 (Transparency & Receipts)
Version: 0.2.0
Date: 2026-07-18
Audience: implementers building or operating an ANS Transparency Log (TL), and AHPs and verifiers consuming SCITT receipts

## 1. Scope

ANS-4 specifies how registration **and identity** events flow into an append-only cryptographic
log that produces verifiable receipts. Trust scoring is out of scope.

ANS-4 specifies:

- The inner-event JCS canonicalization, the sealed envelope, and the leaf-hash rule.
- The `TransparencyLog` contract: append with producer-signature verification, per-object reads, checkpointing.
- The TL's public verification API surface, including the C2SP checkpoint and tile endpoints.
- Producer authentication (RA → TL).
- Receipt distribution: live retrieval.
- Optional checkpoint anchoring to the Hedera Consensus Service per HCS-27 (§7).

ANS-4 is **deployment-optional**. Single-tenant deployments with no cross-organizational trust MAY skip it.

ANS-4 does **not** specify:

- The wire format an RA submits over (HTTPS POST is recommended; the spec is transport-agnostic on this point).

## 2. Terminology

- **SCITT statement**: the unit the TL accepts and seals — the JCS-canonical inner-event payload plus a producer signature. Aligned to [`draft-ietf-scitt-architecture`](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/).
- **Sealed envelope**: the record the TL appends — `{payload: {logId, producer: {event, keyId, signature}}, schemaVersion, signature, status}`, where the outer `signature` is the TL's own attestation. The leaf hash covers the fully signed envelope (§3).
- **SCITT receipt**: the TL's signed statement that it sealed one envelope, returned as a binary COSE_Sign1 that also carries an inclusion proof (§5.2).
- **Producer key**: the signing key an RA instance uses to sign events submitted to the TL. Distinct from the TL's own signing key (which signs checkpoints, receipts, attestations, and status tokens).
- **Checkpoint**: a C2SP signed note recording the log's size and root hash at a point in time. Produced as batches seal; consumed by consistency-proof verifiers.

## 3. Cryptographic standards

| Requirement | Standard | Rule |
| --- | --- | --- |
| Canonicalization | [JCS (RFC 8785)](https://www.rfc-editor.org/rfc/rfc8785) | All JSON payloads MUST be canonicalized before signing or hashing |
| Signature format | [JWS Detached (RFC 7515 Appendix F)](https://www.rfc-editor.org/rfc/rfc7515) | Detached: the payload is not embedded |
| Co-located signatures | JWS Detached | When a signature resides in the same JSON object as its data, the signature fields MUST be excluded from the signed payload. The exclusion scope MUST be explicit |
| Signature wire format | JWS Compact | `<protected_header>..<signature>` (two dots; empty middle section is the detached payload) |
| Algorithms | ES256 (ECDSA P-256/SHA-256) | Every TL-produced signature — checkpoint, attestation, receipt, status token — and every producer key is ES256. The JWS layer additionally recognizes RS256 for interoperability (verified if presented, never emitted) and EdDSA on the ANS-0 identity-proof surface |
| Leaf hash | [RFC 6962 §2.1](https://www.rfc-editor.org/rfc/rfc6962) | `SHA-256(0x00 ‖ JCS(envelope))` over the **fully signed envelope** — including the TL's outer attestation signature. This is the leaf the TL appends and the hash an offline verifier recomputes when walking an inclusion proof |

JWS protected headers: `alg` and `kid` are REQUIRED on every signature; `typ`, `timestamp` (unix
seconds at signing), and `raid` (RA instance identifier, producer signatures only) are OPTIONAL.

**TL signing keys.** Every TL signature — the C2SP checkpoint's primary signature line and its JWS
additional-signer line, the outer envelope attestation, SCITT COSE receipts, and status tokens — is
made with a key advertised as a verifier line at `GET /root-keys` (§5.1). The line set is
append-only and consumers MUST accept multiple lines
([ANS-6 §4.5](ans-6-agent-authentication.md#45-root-keys)); a verifier resolves the 4-byte `kid` in
a receipt's protected header against those lines.

## 4. Transparency Log operations

ANS-4's protocol surface is three operations: append, per-object reads, and checkpointing.

`append` is the write operation. The RA POSTs the raw inner-event body with its producer signature in the
`X-Signature` header (a detached JWS; request bodies are capped at 256 KiB). The TL MUST validate the
signature against the producer-key registry (§6), construct the sealed envelope, append it to the log in
log order, and issue a signed checkpoint covering it within the deployment's checkpoint cadence (§8,
operator policy). The append response is `200` with the assigned `logId`. After producer validation,
submissions with the same `SHA-256(JCS(inner event))` are **duplicates** under the ingest API's
equivalence rule ([`api/api-spec-tl-v2.yaml`](../api/api-spec-tl-v2.yaml)): a duplicate of an
already-sealed event MUST return `200` with `duplicate: true` and the original leaf's `logId`, index,
and hash, and MUST NOT append a second leaf; concurrent duplicate submissions MUST have the same
single-leaf outcome. Receipts are retrieved afterward from the per-object receipt endpoints and
become available once a checkpoint covers the leaf (§5.2).

Bulk reads are the checkpoint endpoints plus the static C2SP tile surface (§5.2); there is no separate paginated range API.

## 5. Public verification API

A conforming TL MUST expose the following REST API surface (HTTPS; JSON unless noted):

| Endpoint | Purpose |
| --- | --- |
| `GET /v1/agents/{agentId}` | Badge: sealed event, TL attestation, inclusion proof, and computed status for one agent |
| `GET /v1/agents/{agentId}/audit` | Paginated history of the agent's events, each with its own proof |
| `GET /v1/agents/{agentId}/receipt` | SCITT COSE receipt for the agent's leaf (binary COSE) |
| `GET /v1/agents/{agentId}/status-token` | Short-lived signed status token (`application/ans-status-token+cbor`, §5.2) |
| `GET /v1/log/checkpoint` | Latest signed checkpoint (JSON view) |
| `GET /v1/log/checkpoint/history` | Checkpoint history with pagination, for consistency-proof verification |
| `GET /v1/log/schema/{version}` | JSON Schema definition for a given event schema version |
| `GET /root-keys` | The TL verification line (§5.1, text/plain) |
| `GET /checkpoint` | The raw C2SP signed checkpoint note (static tile surface) |
| `GET /tile/*` | C2SP tlog-tiles: Merkle tree tiles and entry bundles for bulk verification |

Read-only endpoints require no authentication. Verification MUST NOT require access to producer public keys or knowledge of RA implementation details: every proof verifies against the TL's own published key.

### 5.1 Key distribution

The TL distributes its verification keys via `GET /root-keys` as newline-delimited sumdb-note
verifier lines (text/plain); the 4-byte key hash embedded in each line is the value receipts carry
as the COSE `kid`.

The line set is **append-only**. A TL MAY add a key (a new line); it MUST retain every previously
published line. Keys never expire: removing a line would strand every artifact it signed. Verifiers
cache and merge accordingly
([ANS-6 §4.5](ans-6-agent-authentication.md#45-root-keys)).

### 5.2 Receipts, status tokens, checkpoints

**COSE receipt profile.** A receipt is a COSE_Sign1 (RFC 9052): protected header `{alg: ES256,
kid: <4-byte SPKI key hash>, vds: 1 (RFC 9162 SHA-256), CWT claims: {iss, iat}}`; unprotected
header `{396 (verifiable-data-structure proofs): {-1: treeSize, -2: leafIndex, -3: inclusion
path, -4: rootHash}}`; payload: the sealed envelope. The signature covers the protected header
and the payload only; nothing in the unprotected header, `rootHash` included, is signed.

**What a receipt proves.** A receipt whose signature verifies under a `/root-keys` key is the TL's
authenticated statement that it sealed that envelope.

The inclusion proof serves a separate, optional purpose. Recomputing the leaf hash (§3) and
walking the path yields the root of a tree of `treeSize` leaves; a verifier that compares it with
the root of the TL's checkpoint for the same `treeSize` confirms that the TL published a tree head
containing the leaf. Because the same TL signs both the receipt and the checkpoint it does not
establish the log's honesty; consistency between checkpoints (§9.1), HCS anchoring (§7), and ANS-5
monitoring do that. The `rootHash` in the unprotected header is a convenience copy and MUST NOT be
treated as verified.

**Receipt tree size.** A receipt is issued against a checkpoint that covers its leaf, and a TL
MAY store it and return it unchanged as the tree grows, so a receipt's `treeSize` is normally
below the size in the current `/checkpoint`. That is not staleness, and verifiers MUST NOT treat
it as an invalid receipt, identity, or signature. A verifier performing the publication check on
such a receipt uses the checkpoint the TL signed at that size, served with its signature lines by
`GET /v1/log/checkpoint/history` (`fromSize` and `toSize` equal to `treeSize`), or an RFC 6962
§2.1.2 consistency proof from `treeSize` to the current checkpoint built from the `/tile/*`
surface.

**Status tokens.** `GET /v1/agents/{agentId}/status-token` returns a short-lived signed
assertion of the agent's computed status (`application/ans-status-token+cbor`; default TTL one
hour), signed by the same TL key. Verifiers MUST check the token's expiry themselves.

**Checkpoints and tiles.** The raw checkpoint at `GET /checkpoint` is a C2SP signed note. Its
primary signature line carries `<4-byte keyhash> ‖ <ASN.1 DER ECDSA signature over SHA-256(note
body)>`, base64-encoded per the note format; a standard-JWS additional-signer line is appended to
the same note by the same key. The `GET /tile/*` surface serves the Merkle tree in C2SP
tlog-tiles form for bulk and offline verification. A checkpoint that verifies under a
`/root-keys` key proves that the TL signed that tree head; that the head extends earlier heads is
established by a consistency proof computed from the tiles (§9.1).

### 5.3 Identity surface

This surface applies to the optional
[Verified Identity capability](ans-0-identity-anchor.md#122-optional-capability-verified-identities).
A TL serving an RA without it exposes no `/v1/identities/*` routes and seals no `IDENTITY_*`
events; it remains conformant.

There is **one transparency log — a single Merkle tree.** Every event, agent or identity, is
producer-signed and appended to that one tree in log order. A **"stream"** is the **read view**
selected by its documented endpoint over that single log (by `agentId` or `identityId`), in log
order, never a separate tree. The Verified-Identity
object ([ANS-0 §4](ans-0-identity-anchor.md#4-the-verified-identity-object)) is sealed and read
through this surface; ANS-0 defines the object and the visibility semantics, ANS-4 the routes.

The `IDENTITY_*` family and its sealed fields are defined in
[ANS-0 §8.1](ans-0-identity-anchor.md#81-the-identity-event-family-and-ingest); a sealed identity
log entry MUST validate against
[`api/identity-event-schema-v2.json`](../api/identity-event-schema-v2.json). Proof, rotation, and
revocation events appear on the identity's stream; link/unlink events additionally appear on each
named `ansId`'s identity-history endpoint, never in the agent's lifecycle audit. The TL public read
surface gains:

| Endpoint | Purpose |
| --- | --- |
| `GET /v1/identities/{identityId}` | Latest sealed event + proof + computed `{status, keys[], keysLogId}` for one identity |
| `GET /v1/identities/{identityId}/audit` | Paginated history of the identity's event chain, each with its own proof |
| `GET /v1/identities/{identityId}/receipt` | SCITT COSE receipt for the identity leaf |
| `GET /v1/identities/{identityId}/agents` | Reverse join — currently-linked agents (paginated) |
| `GET /v1/agents/{agentId}/identities` | The computed who-identities list for one agent (paginated) |
| `GET /v1/agents/{agentId}/identities/history` | Link/unlink events naming this agent (audit envelope) |

The agent badge additionally carries the computed `identities[]` join, governed by
[ANS-0 §8.2–§8.3](ans-0-identity-anchor.md#82-computed-reads-and-the-visibility-predicate). These
reads require no authentication; only ingest (§6) requires the producer credential.

## 6. Producer authentication

The TL MUST verify that each event came from an authorized RA instance before sealing it. Every submitted event carries a detached-JWS producer signature in the `X-Signature` header; the TL resolves the `(raid, kid)` pair from the signature's protected header against its producer-key registry and rejects an unknown, expired, or revoked key.

Producer-key registration:

1. The operator generates the producer key pair under the RA's key manager; the private key never leaves the RA instance.
2. The operator registers the public key with the TL (`POST /internal/v1/producer-keys`, admin-gated), supplying the client-chosen `key_id`, the `ra_id`, `public_key_pem` (SPKI), `algorithm` (`ES256`), and the required `valid_from` and `expires_at` window (`valid_from` must precede `expires_at`). A duplicate `key_id` is rejected (409).
3. The TL associates the registered key with its `(ra_id, key_id)`.
4. The RA carries the `kid` and `raid` in the protected header of every statement signature.

Rotation uses an overlap window: new keys are registered with future `valid_from` dates; both old and new
remain active during the transition. Expiry and revocation both gate **new** ingest — an expired or revoked
key can no longer sign events the TL will accept. Already-sealed events are unaffected: the log is
append-only, and verifiers check the TL's own attestations, receipts, and checkpoints against `/root-keys`,
never producer keys.

Agent and identity events ride the **same** producer lane (the same producer-key registry and
signature check) through **separate** ingest routes: `POST /v1/internal/agents/event` and `POST
/v2/internal/agents/event` for the agent event families and `POST /v1/internal/identities/event`
for the identity event family. The TL rejects a cross-lane body — an `IDENTITY_*` payload on an
agent route, or an `AGENT_*` payload on the identity route — with `422 INVALID_EVENT`, so the two
object types never interleave at ingest.

## 7. Checkpoint anchoring to Hedera (HCS)

The TL's checkpoints MAY additionally be published to the [Hedera Consensus Service](https://hedera.com/consensus-service).
The commitment follows
[HCS-27 (Merkle Tree Profile and Proofs)](https://hol.org/docs/standards/hcs-27/merkle-profile/):
the TL publishes periodic Merkle root checkpoints (root hash and tree size) to a designated HCS
topic as typed consensus messages. The HCS-27 "Merkle v1" tree profile is the RFC 9162 §2 Merkle
Tree Hash — SHA-256 with the `0x00` leaf prefix and `0x01` node prefix (§3).

Only cryptographic commitments go on-ledger: log entries, metadata, and proof bundles remain
off-ledger with the TL. A verifier checks an anchored checkpoint by fetching the topic message
from at least two independent HCS mirror nodes, comparing it against the TL's published
checkpoint byte-for-byte, and validating the TL signature via `/root-keys` (§5.1). The operator
publishes the HCS topic ID alongside its TL origin documentation; pinning the topic ID to the
TL's identity is the defense against topic substitution.

## 8. Conformance

A conformant ANS-4 implementation implements §3–§6.

**Operator policy** (rotation cadence, checkpoint batching window, status-token TTL, HCS anchoring cadence) is deployment choice; a conforming verifier MUST NOT reject a receipt because an operator's cadence differs from another deployment's.

## 9. Security considerations

### 9.1 RA / TL collusion

When one operator runs both RA and TL it could forge events with no independent check. The signed
checkpoint and tile history is the log's own mitigation: a rewritten log cannot produce consistent
proofs against previously published checkpoints. HCS anchoring (§7) and running RA and TL under
different operators remove the single-entity risk.

### 9.2 Producer-key compromise

A compromised producer key lets an attacker submit forged events until it is revoked (§6).
Already-sealed events stay verifiable against the TL's own keys, and the sealed history bounds what
could have been injected to the compromise window.

## Appendix A: Worked examples

Non-normative worked examples (sealed envelope, TL badge response, revocation event, producer key registration) live at [`examples/ans-4-examples.md`](examples/ans-4-examples.md).

## 10. References

- ANS-0 specification: [`ans-0-identity-anchor.md`](ans-0-identity-anchor.md). Binding rule, foundational principles.
- ANS-1 specification: [`ans-1-registration.md`](ans-1-registration.md). Event set, registration aggregate, lifecycle.
- ANS-3 specification: [`ans-3-dns-publication.md`](ans-3-dns-publication.md). `_ans-badge` record carrying the TL endpoint pointer.
- ANS-5 specification: [`ans-5-integrity-monitoring.md`](ans-5-integrity-monitoring.md). Integrity Monitor operating principles, verification procedure consuming TL receipts.
- [draft-ietf-scitt-architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/): SCITT Transparency Service.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): JCS canonicalization.
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515): JWS.
- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052): COSE (binary receipt envelope).
- [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962): Merkle tree leaf hashing (§3).
- [HCS-27](https://hol.org/docs/standards/hcs-27/merkle-profile/): Merkle Tree Profile and Proofs — HCS checkpoint anchoring (§7).
- [C2SP tlog-checkpoint / tlog-tiles](https://c2sp.org/): checkpoint note and tile formats (§5.2).
