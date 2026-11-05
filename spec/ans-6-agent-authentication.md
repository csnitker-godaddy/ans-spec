# ANS-6: Agent-to-Agent Authentication

Status: DRAFT v1.0
Spec: ANS-6 (Agent-to-Agent Authentication)
Version: 0.1.0
Date: 2026-08-24
Audience: implementers building ANS-aware agent runtimes and SDKs (caller and callee sides), and operators deploying agent-to-agent authentication

## 1. Scope

ANS-6 is the verifier-facing layer: it specifies how one agent authenticates another at request
time, consuming the artifacts the other layers produce — the Identity and Server Certificates
([ANS-1](ans-1-registration.md), [ANS-2](ans-2-versioned-naming.md)), the published DNS records
([ANS-3](ans-3-dns-publication.md)), and the Transparency Log's badge, receipt, and status token
([ANS-4](ans-4-transparency.md)). Where [ANS-5](ans-5-integrity-monitoring.md) specifies periodic
out-of-band monitoring, ANS-6 specifies the per-request path between two agents.

Authentication decomposes along two independent axes:

- **Verification tier** — where the trust evidence comes from. The **badge tier** queries the TL
  at connection time and trusts its response. The **SCITT tier** verifies receipt and status-token
  artifacts locally, with no per-request network calls.
- **Possession-proof method** — how the caller proves it holds its identity key. **Method A
  (mTLS)** presents the Identity Certificate in the TLS handshake ([ANS-2
  §4](ans-2-versioned-naming.md#4-mtls-with-identity-certificates)). **Method B (application-layer
  proof of possession)** carries an RFC 9449 DPoP proof in an HTTP header, surviving L7 proxies
  and gateways that terminate TLS.

A conformant callee implements at least one method and documents which (§10).

ANS-6 does **not** specify:

- Authorization. Every procedure in this document AUTHENTICATES a peer — it establishes *who* is
  calling, never *what* they may do. The callee MUST apply its own authorization to the
  authenticated identity.
- Delegation across a call chain.
- Trust scoring.
- The periodic integrity checks of the AIM ([ANS-5 §4](ans-5-integrity-monitoring.md#4-verification-checks)).

## 2. Terminology

- **Caller / callee**: the agent initiating an HTTP request / the agent serving it. Matches the
  usage of [ANS-2 §4](ans-2-versioned-naming.md#4-mtls-with-identity-certificates).
- **Badge**: the TL's JSON response for an agent's most recent sealed event
  (`GET /v1/agents/{agentId}`, [ANS-4 §5](ans-4-transparency.md#5-public-verification-api)),
  carrying the event, a Merkle inclusion proof, a computed `status`, and the TL's signature.
- **Receipt**: a COSE_Sign1 structure carrying an agent's sealed leaf, its RFC 9162 inclusion
  path, and the TL's signature over the leaf (§4.3). Proves *identity*: the agent's registration
  is in the log.
- **Status token**: a short-lived COSE_Sign1 structure asserting an agent's current lifecycle
  state with bounded staleness. Proves *liveness*: the registration is currently valid.
- **Possession proof**: evidence that the caller holds the Identity Certificate's private key for
  this request — the mTLS `CertificateVerify` in Method A, the DPoP proof in Method B.
- **Verification tier**: badge tier (online) or SCITT tier (offline), per §3.2.
- **Possession-proof method**: Method A (mTLS) or Method B (application-layer DPoP), per §3.3.
- **Replay cache**: the callee-side state, however realized, that enforces single-use DPoP proof identifiers (§7.6).

## 3. Verification model

### 3.1 The three proofs

Authenticating a peer establishes three independent facts, all bound to one certificate:

| Proof | Question answered | Provided by |
| --- | --- | --- |
| **Identity** | Is this certificate sealed in the Transparency Log for this agent? | Badge (badge tier) or receipt (SCITT tier) |
| **Liveness** | Is that registration valid *right now* (ACTIVE, not revoked)? | Badge `status` (badge tier) or status token (SCITT tier) |
| **Possession** | Does the peer hold the certificate's private key, for *this* connection or request? | TLS handshake (Server Certificate for callees; Identity Certificate under Method A) or DPoP proof (Method B) |

All three are required: without possession anyone can replay public artifacts; without liveness a
revoked agent passes.

### 3.2 Verification tiers

| Tier | Artifacts | Trust model | Per-request network calls |
| --- | --- | --- | --- |
| **Badge** | Badge JSON fetched from the TL | Trust the TL's response at query time | DNS lookup + TL query (cacheable) |
| **SCITT** | Receipt + status token, presented in HTTP headers | Verify signatures and Merkle proof locally | None — verification is local computation (under Method B the replay cache adds authority-wide callee-side state, §7.6) |

The SCITT tier is RECOMMENDED; the badge tier remains supported. A SCITT verifier falls back to
the badge tier when a peer presents no artifacts (§9).

### 3.3 Possession-proof methods

| Property | Method A: mTLS | Method B: application-layer PoP (DPoP) |
| --- | --- | --- |
| Proof mechanism | Identity Certificate + `CertificateVerify` in the TLS handshake | RFC 9449 DPoP proof in the `DPoP` request header |
| Survives TLS-terminating proxies | No — the L7 hop drops the client identity | Yes — the proof rides the HTTP request end to end |
| Channel binding | Yes — the proof is the channel | No — the channel is server-authenticated HTTPS only |
| Request binding | No — the handshake authenticates the connection, not individual requests | Yes — each proof binds one HTTP method + URL + content, single-use |
| Trust anchor for the caller's certificate | Chain to the RA's Private CA ([ANS-2 §3](ans-2-versioned-naming.md#3-the-identity-certificate)) | Status token's `validIdentityCerts` fingerprint set (§7.5) |
| Callee-side state | None beyond TLS | Replay cache (§7.6) |

In both methods the **callee** is authenticated the same way: TLS server authentication provides
its possession proof, and §5 provides its identity and liveness checks. The methods differ only
in how the **caller** proves itself. Method B binds a request, not the channel; its proof is
visible to TLS-terminating intermediaries, and headers and query parameters are outside
`ans_content_digest`.

### 3.4 Composing tiers and methods

Method A composes with either tier: the mTLS handshake authenticates the caller's certificate,
and the badge (§6.2) or the caller's SCITT artifacts (§6.3) establish identity and liveness.
Method B requires the SCITT tier: its binding checks run against the status token's certificate
fingerprint arrays (§7.5).

## 4. Verification artifacts

### 4.1 Badge

`GET /v1/agents/{agentId}` on the TL returns the badge: the agent's most recent sealed event
wrapped in the TL envelope, with a Merkle inclusion proof (`merkleProof`), its current derived
`status`, and the TL's signature over the payload. The envelope is `schemaVersion: "V2"`; the
inner event carries `ansId`, `ansName`, `agent {host, name, version, providerId}`, and
`attestations` with certificate **arrays**. A worked response lives at [ANS-4 example
A.2](examples/ans-4-examples.md#a2-tl-badge-response); the machine-readable schema is
[`api/tl-response-schema-v2.json`](../api/tl-response-schema-v2.json).

Key paths a verifier reads:

| Value | Path |
| --- | --- |
| Status | `.status` |
| ANSName | `.payload.producer.event.ansName` |
| Agent host | `.payload.producer.event.agent.host` |
| Agent version | `.payload.producer.event.agent.version` |
| Server Certificate fingerprints | `.payload.producer.event.attestations.serverCerts[].fingerprint` |
| Identity Certificate fingerprints | `.payload.producer.event.attestations.identityCerts[].fingerprint` |
| Event type | `.payload.producer.event.eventType` |

Certificate fingerprints are `SHA256:` followed by the lowercase-hex SHA-256 of the full
DER-encoded certificate — the same value carried in the Server DANE TLSA record ([ANS-3
§6.3](ans-3-dns-publication.md#63-family-trust-records)). Both certificate fields are arrays; a
presented certificate matches when its fingerprint equals **any** entry (§8.2).

Status values and their connection semantics:

| Status | Meaning | Valid for connections? |
| --- | --- | --- |
| `ACTIVE` | Registered and in good standing | Yes |
| `WARNING` | Certificate expires soon (RA-configured window) | Yes |
| `DEPRECATED` | The AHP has marked this version for retirement | Yes, with a migration signal |
| `EXPIRED` | Certificate has expired (terminal) | No |
| `REVOKED` | Registration explicitly revoked (terminal) | No |

The badge's computed `status` MAY additionally report `UNKNOWN` when the TL cannot compute a
status for the entry; verifiers treat `UNKNOWN` as an inability to verify (apply the §9 failure
policy), never as a pass. Status tokens carry only the five values above (§4.4).

### 4.2 The `_ans-badge` record and trusted TL domains

The badge tier bootstraps from the `_ans-badge.{agentHost}` TXT record, emitted as a family trust
record by every discovery profile ([ANS-3 §6.3](ans-3-dns-publication.md#63-family-trust-records)):

```text
_ans-badge.agent.example.com. IN TXT "v=ans-badge1; version=v1.0.0; url=https://transparency-log.example.com/v1/agents/7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07"
```

To parse: split on `;`, trim whitespace, read `v` (format tag, `ans-badge1`), `version` (the
registration's semver, `v`-prefixed, matching the ANSName's version segment), and `url` (the TL
badge endpoint). Multiple records coexist during version changes; the `version` field selects the
right one without fetching every badge (§8.1). Absence of the record under `_ans-badge` means the
host is not a registered ANS agent.

Discovery records ([ANS-3 §6](ans-3-dns-publication.md#6-discovery-profiles)) locate the endpoint
and carry no authentication weight; they never substitute for the badge, receipt, or status token.

**Before fetching any badge URL, the verifier MUST confirm the URL's host is a TL the verifier
trusts.** Verifiers maintain an explicit allowlist of trusted TL domains; the DNS record locates
the badge, it does not confer trust on the endpoint it names.

The allowlist MUST come from configuration or an out-of-band channel the operator already trusts.
It MUST NOT be derived from the DNS records under verification, and trust-on-first-use from a
first badge fetch is NOT RECOMMENDED.

### 4.3 Receipt

`GET /v1/agents/{agentId}/receipt` returns the SCITT receipt for the agent's latest sealed event
(`Content-Type: application/scitt-receipt+cose`). The receipt is a COSE_Sign1 structure (CBOR
tag 18):

| Component | Contents |
| --- | --- |
| Protected header | `1` (alg) = `-7` (ES256); `4` (kid) = 4-byte key id, `SHA-256(SPKI-DER)[0:4]` of the signing key, cross-referenced against `/root-keys` (§4.5); `395` (vds) = `1` (RFC9162_SHA256); `15` (cwt-claims) = `{1 (iss), 6 (iat)}` |
| Unprotected header | `396` (vdp): the inclusion proof — `-1` tree_size (uint64), `-2` leaf_index (uint64), `-3` hash_path (array of 32-byte hashes), and optionally `-4` root_hash (32 bytes; **advisory** — see below) |
| Payload | The JCS-canonicalized ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) sealed leaf bytes ([ANS-4 §3](ans-4-transparency.md#3-cryptographic-standards)), **attached** |
| Signature | 64-byte ECDSA P-256, IEEE P1363 `R \|\| S` |

The Merkle leaf is `SHA-256(0x00 || leaf_bytes)` and interior nodes are
`SHA-256(0x01 || left || right)`, per [RFC 9162 §2.1](https://www.rfc-editor.org/rfc/rfc9162)
and the ANS-4 §3 leaf-hash rule. Implementations MUST canonicalize with JCS before hashing.

The COSE_Sign1 signature covers only the protected header and the payload. The inclusion proof
rides the **unprotected** header and is not covered by the signature; `root_hash` at vdp `-4`
MUST NOT be treated as verified. Tree-head trust comes from the signed checkpoint
([ANS-4 §5.2](ans-4-transparency.md#52-receipts-status-tokens-checkpoints)).

A `503` with `Retry-After` means the leaf is appended but not yet covered by a signed checkpoint;
retry after the indicated delay.

**Receipt verification algorithm:**

```text
Input: receiptBytes, trusted key set (from /root-keys)

1. Decode CBOR tag 18 → [protected, unprotected, payload, signature]
2. Look up the key by protected[4] (kid)
3. Reconstruct Sig_structure = CBOR(["Signature1", protected, h'', payload]);
   verify ECDSA-P256(key, SHA-256(Sig_structure), signature)
   — signature FIRST, before the issuer check and any Merkle work, so an
   unauthenticated input can neither probe the key store nor buy computation
4. When the protected header carries a cwt-claims iss, assert it equals the
   trusted key's name
5. Read the inclusion proof from unprotected[396]:
   tree_size, leaf_index, hash_path
6. leaf_hash = SHA-256(0x00 || payload)
7. Walk the inclusion path (RFC 9162 §2.1.3.2):
   fn = leaf_index; sn = tree_size - 1; r = leaf_hash
   for each p in hash_path:
     reject if sn == 0                 // excess path elements
     if fn is odd OR fn == sn:
       r = SHA-256(0x01 || p || r)
       if fn is even:                  // right-border node
         right-shift fn and sn until fn is odd or fn == 0
     else:
       r = SHA-256(0x01 || r || p)
     fn >>= 1; sn >>= 1
   reject if sn != 0                   // insufficient path elements
   computed_root = r
8. computed_root is an OUTPUT, not a check: nothing in the receipt
   authenticates it (the VDP is unprotected). Compare it against the TL's
   signed checkpoint when tree-head trust is required; ignore any advisory
   vdp[-4] value for verification purposes.
```

A receipt never goes stale — the tree is append-only, so a valid inclusion proof is valid
forever. It also never proves liveness: a receipt for a since-revoked agent still verifies.
Always pair it with a status token or badge status check (§3.1).

### 4.4 Status token

`GET /v1/agents/{agentId}/status-token` returns the status token
(`Content-Type: application/ans-status-token+cbor`), a COSE_Sign1 (CBOR tag 18) whose protected
header carries `1` (alg) = `-7`, `4` (kid) as in §4.3, and `3` (content type) =
`"application/ans-status-token+cbor"`. The payload is a CBOR map with integer keys:

| Key | Field | Type |
| --- | --- | --- |
| 1 | `agentId` | UUID string |
| 2 | `status` | `ACTIVE`, `WARNING`, `DEPRECATED`, `EXPIRED`, `REVOKED` |
| 3 | `iat` | int64, Unix seconds |
| 4 | `exp` | int64, Unix seconds (default TTL one hour) |
| 5 | `ansName` | e.g. `ans://v1.0.0.agent.example.com` |
| 6 | `validIdentityCerts` | array of cert entries |
| 7 | `validServerCerts` | array of cert entries |
| 8 | `metadataHashes` | map: protocol → `SHA256:...` |

Each cert entry is itself an integer-keyed map: `1` = fingerprint — the 32-byte raw SHA-256 as a
CBOR byte string (decoders SHOULD also accept the `SHA256:<hex>` text form) — and `2` =
certificate type, drawn from the `CertificateExtended.type` enum of the V2 schema (e.g.
`X509-OV-CLIENT`, `X509-DV-SERVER`). The type is informational: verification decisions compare
fingerprints, never types, and consumers SHOULD compare the type case-insensitively. The arrays
list **every currently-valid certificate**, so both old and new fingerprints appear during a
rotation overlap and a verifier matches against any entry. `metadataHashes` lets a
verifier hash a fetched Agent Card and detect post-registration tampering
([ANS-5 §4](ans-5-integrity-monitoring.md#4-verification-checks), schema-integrity row).

Under `ANS_DNSAID` the same digest appears as `key65401` (base64url raw bytes) on the SVCB row
([ans-dnsaid §2](discovery-profiles/ans-dnsaid.md#2-record-assembly)); a verifier checking card
integrity SHOULD compare both where available, and disagreement is itself a finding.

**Status-token verification algorithm:**

```text
Input: tokenBytes, trusted key set, clock-skew tolerance (≤ 10 minutes)

1. Decode CBOR tag 18 → [protected, unprotected, payload, signature]
2. Look up the key by protected[4] (kid)
3. Reconstruct Sig_structure = CBOR(["Signature1", protected, h'', payload])
4. Verify ECDSA-P256(key, SHA-256(Sig_structure), signature)
5. When cwt-claims iss is present, assert it equals the trusted key's name
   (after the signature, as in §4.3 step 3)
6. Decode the integer-keyed payload
7. Assert now ≤ exp + skew
8. Assert status is not terminal (EXPIRED, REVOKED)
```

**Terminal states return `410 Gone`, not a token.** The TL refuses to issue status tokens for
EXPIRED or REVOKED agents; the absence of a fresh token *is* the revocation signal. Verifiers
MUST treat the inability to obtain a fresh status token as equivalent to revocation, subject to
the failure policy in §9. A `501` means the deployment has not enabled status tokens; clients
fall back to the badge tier.

### 4.5 Root keys

Verifiers obtain the TL's verification key once from `GET /root-keys`
([ANS-4 §5.1](ans-4-transparency.md#51-key-distribution)), served as newline-delimited
[C2SP signed-note](https://c2sp.org/signed-note) verifier lines:

```text
<name>+<key_hash>+<base64 key material>
```

`name` is the TL's domain identifier; `key_hash` is the hex-encoded first 4 bytes of
SHA-256(SPKI-DER) and equals the `kid` (label 4) in receipt and status-token protected headers;
the key material is the base64 ECDSA P-256 public key (SubjectPublicKeyInfo DER, optionally
preceded by the C2SP key-type octet `0x02`). Parsers MUST recompute the hash from the decoded
SPKI and reject a line whose declared `key_hash` disagrees.

Parsers MUST accept multiple lines ([ANS-4 §3](ans-4-transparency.md#3-cryptographic-standards)).
Verifiers fetch each trusted TL's lines once at bootstrap and cache them.

The `/root-keys` line set is append-only ([ANS-4 §5.1](ans-4-transparency.md#51-key-distribution)).
Verifier-side cache rules:

- **Merge additively.** A refresh adds unknown lines to the cache and MUST NOT drop a cached key
  that is absent from the response — a cached key remains valid for verifying the artifacts it
  signed, indefinitely.
- **Refresh on unknown `kid`.** On a receipt or status token whose `kid` matches no cached key,
  the verifier SHOULD re-fetch `/root-keys` once and retry the lookup before rejecting (§9.5).
  Refreshes MUST be rate-limited with a cooldown on the order of minutes: unknown kids arrive on
  attacker-supplied input, and an ungated trigger is a fetch amplifier.
- **Collisions fail toward the cache.** A fetched line whose `kid` matches a cached key but whose
  name or key material differs is discarded and logged as a finding; the first-seen key wins.
- **Fetch failure keeps the cache.** A failed refresh leaves the existing snapshot in place, and
  verification continues against cached keys.

### 4.6 HTTP header transport and refresh

SCITT-tier artifacts travel as HTTP headers on the requests and responses agents already
exchange:

| Header | Direction | Contents |
| --- | --- | --- |
| `X-SCITT-Receipt` | Both — callers send it on requests, callees on responses | Standard-base64 COSE_Sign1 receipt |
| `X-ANS-Status-Token` | Both | Standard-base64 COSE_Sign1 status token |
| `DPoP` | Requests only (Method B) | Compact-JWS DPoP proof (§7.2) |

Agents SHOULD include their artifacts on **every** request and response, not only the first.
Re-presentation does not imply re-verification: a receiver MAY reuse cryptographic verification
results for byte-identical artifacts, provided every authentication decision still satisfies the
applicable trust, identity-binding, status, freshness, and expiry rules (§4.4, §9.4, §11.1; a
receipt's signature does not expire with the status token it accompanies). The Method-B
possession proof is the exception — it is single-use and MUST be verified on every request (§7.4).
Each of these headers, plus `Authorization` (which drives the token binding in §7.8), MUST appear
at most once; a verifier MUST reject a request carrying duplicates. Receivers MUST bound decoded
header sizes before parsing. Deployments MAY also staple both artifacts into the Agent Card; the
headers are the mechanism this spec verifies.

Each agent obtains and refreshes its own artifacts from the TL; peers never fetch them on its
behalf. Refreshing in the background, before expiry, keeps the TL out of the agent's own request
path and is RECOMMENDED; caller-side acquisition timing is otherwise implementation-defined:

- **Status token**: refreshed before expiry, subject to the freshness and failure rules in §9.
- **Receipt**: re-fetched only when the agent's latest sealed event changes — certificate
  rotation or a version's registration ([ANS-1 §7](ans-1-registration.md#7-lifecycle-operations)).

## 5. Authenticating a callee

The caller authenticates the agent it is connecting to. Both tiers end the same way: the
callee's live Server Certificate must match a sealed fingerprint, and the sealed `agent.host`
must equal the host the caller actually dialed.

### 5.1 Badge tier

1. **DNS lookup.** Query `_ans-badge.{calleeHost}` TXT (§4.2). No record → not a registered ANS
   agent. Multiple records → select the version the caller intends to call when it knows one;
   otherwise prefer `ACTIVE` and disambiguate by certificate fingerprint after the handshake
   (§8.1 — callees announce no version at the TLS layer).
2. **Trusted-TL check, then fetch.** Confirm the badge URL's host is a trusted TL, then fetch the
   badge.
3. **Status.** `ACTIVE` / `WARNING`: proceed. `DEPRECATED`: proceed, prefer an ACTIVE sibling
   version when one exists (§8.1). `EXPIRED` / `REVOKED`: reject.
4. **TLS handshake and comparison.** Connect over TLS; validate the chain to a trusted public CA
   as usual; compute `SHA-256(cert.Raw)` over the presented Server Certificate; require the
   fingerprint to equal some entry of `attestations.serverCerts[]`; require `agent.host` to equal
   the host the caller resolved and dialed, and require the certificate to pass standard
   [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125) hostname verification against that same
   requested name. The `agent.host` comparison is in addition to, never in place of, the standard
   hostname check: every field the badge carries was chosen by whoever published it, so only the
   dialed name ties verification to the peer the caller meant to reach.
5. **Optional.** DANE/TLSA pinning (§5.3).

Badge fetch MAY precede or follow the handshake; no application data is trusted until the
comparison completes.

### 5.2 SCITT tier

The callee sends its receipt and status token in response headers; the caller verifies locally.

1. **TLS handshake** as in §5.1 step 4; capture the Server Certificate.
2. **Extract artifacts** from the response headers (§4.6). Either header absent → fall back to
   the badge tier.
3. **Verify the receipt** (§4.3 algorithm). Malformed → fall back to badge tier; a *failed*
   Merkle proof or signature → reject (§9).
4. **Verify the status token** (§4.4 algorithm). Expired → fall back per §9; terminal status →
   reject.
5. **Bind to the connection.** The Server Certificate's fingerprint must equal some
   `validServerCerts` entry; the receipt event's `agent.host` must equal the host the caller
   resolved and dialed, and the certificate must pass standard hostname verification against that
   same requested name (§5.1 step 4); the receipt
   event and status token must name the same agent (full `ansName`, and the agent identifier when
   both carry one). Optionally compare `metadataHashes` against a fetched Agent Card.

### 5.3 DANE/TLSA (optional, both tiers)

Where the callee's zone is DNSSEC-signed, the caller MAY additionally validate the Server
Certificate against the `_{port}._tcp.{agentHost}` TLSA record set (`3 1 1` or `3 0 1` — DANE-EE,
SHA-256; [ANS-3 §6.3](ans-3-dns-publication.md#63-family-trust-records)), evaluating each record
under its own selector and matching type: selector 1 is SHA-256 over the Server Certificate's
SubjectPublicKeyInfo DER, selector 0 is SHA-256 over the full DER certificate and equals the
fingerprint the badge and status token carry. The `{port}` label is the port the connection
actually uses — under `ANS_DNSAID` the SVCB row's `port=` SvcParam, under `ANS_TXT` the endpoint
URL's port. Check against **all** TLSA records — a match on any one of them suffices. Per RFC
6698 §4, a TLSA RRset that does not DNSSEC-validate as "secure" is unusable and MUST be ignored
rather than trusted.

## 6. Authenticating a caller — Method A: mTLS

The caller presents its Identity Certificate in the TLS handshake per
[ANS-2 §4](ans-2-versioned-naming.md#4-mtls-with-identity-certificates). The handshake proves
possession; this section specifies the identity and liveness verification the callee runs before
processing application data.

### 6.1 Handshake and identity extraction

1. The TLS layer validates the client certificate chain against the RA Private CA trust anchor.
   No chain → reject at the TLS layer.
2. Extract from the validated certificate:
   - **DNS SAN** (also the CN): the caller's FQDN, e.g. `caller.example.com`.
   - **URI SAN**: the full ANSName, e.g. `ans://v1.0.0.caller.example.com` ([ANS-2
     §3](ans-2-versioned-naming.md#3-the-identity-certificate)). No URI SAN → not an ANS Identity
     Certificate.
3. Parse the version from the URI SAN: strip the leading `ans://` and the trailing `.{FQDN}`
   (using the DNS SAN's FQDN); the remainder is the `v`-prefixed version.

The handshake completes before verification, but the callee MUST NOT process application requests
until verification finishes. Cache verified results per §4.6.

Chain validation carries no revocation signal (the private CA publishes no CRL or OCSP); the TL
is the revocation channel — the badge computes `REVOKED` and the status-token endpoint returns
`410` (§4.4) — so §6.2/§6.3 verification is REQUIRED after a successful handshake. A deployment
whose CA publishes revocation MAY also check it.

### 6.2 Badge tier

1. Query `_ans-badge.{callerFQDN}` TXT. When multiple records exist, select the record whose
   `version` field equals the version from the URI SAN (§8.1). Apply the trusted-TL check (§4.2)
   before fetching.
2. Fetch the badge and validate:

| Client certificate | Badge field | Requirement |
| --- | --- | --- |
| DNS SAN | `.payload.producer.event.agent.host` | Equal |
| URI SAN | `.payload.producer.event.ansName` | Equal |
| Fingerprint (`SHA-256(cert.Raw)`) | `.payload.producer.event.attestations.identityCerts[]` | Matches any entry |
| — | `.status` | `ACTIVE`, `WARNING`, or `DEPRECATED` |

### 6.3 SCITT tier

The caller sends its receipt and status token in the request headers (§4.6). The callee verifies
both artifacts locally (§4.3, §4.4) and binds them to the presented certificate:

| Client certificate | Artifact field | Requirement |
| --- | --- | --- |
| Fingerprint | Status token `validIdentityCerts` | Matches any entry |
| DNS SAN | Receipt event `agent.host` | Equal |
| URI SAN | Receipt event `ansName` / status token `ansName` | Equal |
| — | Status token `status` | Not terminal |
| — | Status token `exp` | Not expired |

Either header absent → fall back to the badge tier (§6.2).

### 6.4 Authorization placement

ANS verification authenticates; the callee authorizes separately (allowlist, RBAC — out of ANS
scope). Where authorization decisions depend on registered properties (status, attestations), run
them after ANS verification.

## 7. Authenticating a caller — Method B: application-layer proof of possession

Method B moves the caller's possession proof from the TLS handshake to the application layer as a
[DPoP](https://www.rfc-editor.org/rfc/rfc9449) proof carried in the standard `DPoP` header over
ordinary server-authenticated HTTPS. No client certificate appears in the handshake, so the proof
survives L7 proxies, gateways, and any hop that terminates TLS. OAuth 2.0 composes on top,
unchanged, when a deployment adds one (§7.8).

### 7.1 The three proofs under Method B

| Proof | Provided by |
| --- | --- |
| Identity | SCITT receipt in `X-SCITT-Receipt` (§4.3) |
| Liveness | Status token in `X-ANS-Status-Token` (§4.4) |
| Possession | DPoP proof in `DPoP` |

All three MUST bind to one Identity Certificate (§7.5). The receipt is REQUIRED by default; a
deployment MAY operate in a reduced mode that accepts status token + proof alone, trading away
the request-time inclusion proof, and MUST document the choice.

### 7.2 Proof format

The proof is a compact JWS in the `DPoP` request header, wire-conformant to RFC 9449 §4.2. The
JOSE protected header is **exactly**:

| Parameter | Value |
| --- | --- |
| `typ` | `dpop+jwt` |
| `alg` | `ES256` (the only accepted algorithm) |
| `jwk` | The bare public key: exactly `{kty: "EC", crv: "P-256", x, y}` with full-width (32-byte) base64url coordinates. Required by RFC 9449 §4.2; MUST NOT carry any other member — a private-key `d` fails closed |
| `x5c` | Exactly one entry: the caller's Identity Certificate, standard-base64 DER (RFC 7515 §4.1.6) |

Verifiers MUST decode the header strictly: any JOSE header parameter beyond these four — a
smuggled `kid`, `crit`, anything — rejects the proof. The `jwk` and the `x5c[0]` certificate MUST
present the same public key, compared byte-for-byte on the curve coordinates **before any
signature work**, so the signature is only ever checked under one key and a swapped `jwk` fails
closed. `x5c` is limited to one entry; trust comes from the status token (§7.5), not a chain, and
a second entry is never consulted. Rejection messages SHOULD name the offending parameter.

The payload claims:

| Claim | Value |
| --- | --- |
| `htm` | The HTTP method of the request |
| `htu` | The normalized target URI (§7.3) |
| `iat` | Issue time, Unix seconds |
| `jti` | Unique proof id, ≤ 128 bytes. Signers SHOULD generate ≥ 96 bits of randomness; verifiers can only enforce presence and the size cap |
| `ath` | Only when the request presents an access token: `base64url(SHA-256(token))` (§7.8) |
| `ans_profile` | OPTIONAL. A positive JSON integer identifying the Method-B profile revision; absence means revision `1`, the only revision this document defines. Verifiers MUST reject malformed values and revisions they do not support (§7.11) |
| `ans_content_digest` | REQUIRED. `base64url(SHA-256(content))`, without padding, over the request content defined by RFC 9110 §6.4: after transfer-coding removal, with any content coding still applied. Requests without content carry the digest of the empty octet string (§7.12) |

Verifiers MUST ignore payload claims they do not understand, as required by
[RFC 7519 §4](https://www.rfc-editor.org/rfc/rfc7519#section-4), while enforcing every claim
defined by the supported profile revision. Only the header is closed. Verifiers MUST bound the
proof's size before parsing (the reference profile caps it at 8 KiB).

### 7.3 `htu` normalization

Both signer and verifier normalize the target URI to the RFC 9449 §4.3 form before comparison:
lowercase the scheme and host, drop the scheme's default port (`:443` / `:80`), strip the query
and fragment, and normalize an empty path to `/`. The path is otherwise preserved byte-for-byte
(case-sensitive, no dot-segment or percent-encoding normalization); a path-rewriting hop breaks
the binding. Because `htu` excludes the query string, request parameters are not bound —
deployments MUST NOT put authority-bearing parameters in the query string of a Method-B endpoint.

### 7.4 Verification procedure

Request-level preflight: reject the request when any of `DPoP`, `Authorization`,
`X-SCITT-Receipt`, or `X-ANS-Status-Token` appears more than once, and when the request's
authority is outside the configured trusted set (§7.7).

Then, in order, cheapest and least stateful first:

1. Proof size within bound; compact JWS structure splits into three segments.
2. Strict header decode (§7.2); `typ` and `alg` match; `jwk` present; `x5c` has exactly one
   entry. Decode the payload; reject a malformed or unsupported `ans_profile` and a missing or
   malformed `ans_content_digest` (§7.2).
3. Parse `x5c[0]`; the leaf key MUST be ECDSA P-256; the certificate's validity period MUST
   contain the current time (§7.5).
4. `jwk` equals the certificate key, byte-for-byte.
5. JWS signature verifies under that single key.
6. `htm` equals the request's HTTP method.
7. `htu` equals the normalized expected URL (§7.3, authority per §7.7).
8. Token binding: `ath` ⟺ presented access token, both directions (§7.8).
9. `iat` within the freshness window: `|now − iat| ≤ skew` (default 120 seconds).
10. `jti` present and within the size bound.
11. Verify the status token and (unless the deployment waives it) the receipt; run the binding
    checks of §7.5.
12. Verify `ans_content_digest` against the received content, including empty content (§7.12).
    Enforce content-size limits before hashing; hashing starts only after step 11 succeeds.
13. **Record the `jti` in the replay cache last** — only after every other check, including the
    status-token and content bindings, has passed (§7.6).

### 7.5 Binding to the ANS identity

The certificate that signed the proof must be the certificate the TL vouches for:

1. **Fingerprint.** `SHA-256(x5c[0] DER)` MUST equal some entry of the status token's
   `validIdentityCerts`.
2. **Name.** The certificate MUST carry an `ans://` URI SAN ([ANS-2
   §3](ans-2-versioned-naming.md#3-the-identity-certificate)) whose host equals the status
   token's `ansName` host (case-insensitive). No URI SAN fails closed. Verifiers MAY require full
   ANSName equality.
3. **Receipt agreement.** When a receipt is presented, the sealed event in its leaf payload MUST
   name the same agent as the status token: equal `ansName` — compared case-insensitively over
   the **full** name, version segment included — and equal agent identifier when both artifacts
   carry one. A leaf naming no agent at all is invalid.
4. **Peer pinning (optional).** A callee that only accepts known peers compares the authenticated
   ANSName host against its configured set.

**Certificate validity is checked.** Verifiers MUST reject a proof whose `x5c[0]` validity period
does not contain the current time (`notBefore ≤ now ≤ notAfter`, allowing the §7.4 step 9 skew
tolerance). The status token cannot provide this bound: rotation is additive
([ANS-1 §7](ans-1-registration.md#7-lifecycle-operations)) and sealed fingerprint arrays are
immutable, so an expired or rotated-away certificate is never pruned from `validIdentityCerts`.

Verifiers do not perform CA-chain, key-usage, or certificate-type checks on `x5c[0]`; the status
token — signed by the TL, bounded by `exp` — is the trust statement about the certificate's
registration. Deployments MAY layer X.509 policy on top. This deviates from
[RFC 7515 §4.1.6](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6) (§7.9).

The authenticated result is the status token's `ansName` and `agentId`, the proof certificate's
fingerprint, and the key's RFC 7638 thumbprint (for §7.8).

### 7.6 Replay protection

Each proof is single-use. A given `jti` MUST be accepted at most once across all replicas
accepting Method-B proofs for the same `htu` authority, including when the same proof is
presented concurrently to different replicas. The state that enforces this is the replay cache,
however realized; it MUST satisfy:

- **Retention** until at least `iat + skew + grace` per entry (a small grace, e.g. 5 seconds,
  closes the boundary gap between the two checks). Restart, failover, or partition reassignment
  MUST preserve this protection for the remaining window or fail closed.
- **Bounded.** The state MUST be bounded in size. The `jti` size cap (§7.2) makes a bound in
  entries also a bound in bytes.
- **No early eviction.** An entry MUST NOT be discarded before its retention deadline to make
  room for new requests; a realization that would need to evict MUST instead reject.
- **Fail closed.** State at capacity, unavailable, erroring, or timing out rejects the request; it
  never silently admits a possibly-replayed proof. The replay decision MUST complete within a
  bounded time.
- **Record after trust.** The `jti` is committed only after the full §7.4 pipeline, including the
  status-token and content bindings, succeeds, and before application processing. Recording
  earlier lets anyone with a self-signed certificate flood the bounded state and fail-close
  authentication for every legitimate caller.
- **Every accepting replica.** An in-process store satisfies the single-use rule only when no
  proof can reach more than one replica and replay history survives failover. Otherwise the
  deployment MUST arrange that all replicas serving the authority agree — a shared store, or
  partitioning with recovery guarantees — so that a proof accepted by one replica is rejected by
  every other. Size the state for the in-flight window: `maxEntries ≥ peak RPS × (skew + grace)`
  — and alarm on occupancy before saturation starts rejecting callers.

### 7.7 The `htu` authority requirement

The comparison URL MUST NOT be derived from the request's own `Host` header: the client controls
it, so a proof captured against another origin would pass. Every production deployment MUST
configure one (or both) of:

- **A trusted-authority allowlist** — the externally-visible authorities this callee answers as,
  compared case-insensitively with default ports dropped; requests for any other authority are
  rejected before proof verification.
- **An externally-configured URL** — a trusted authority joined with **this request's** path. The
  authority MUST come from a trusted source: static configuration, or a header the fronting proxy
  sets and strips from clients — never a raw client-supplied `X-Forwarded-*`. The reconstruction
  MUST incorporate the request's path: a constant URL collapses `htu` to one value, so a proof
  minted for any path is accepted on every path and only `htm` still binds the target.
  Implementations SHOULD detect, before serving traffic, a configured reconstruction that does not
  vary with the request path, and refuse Method-B requests until it is corrected.

A Method-B verifier with neither configured MUST reject every Method-B request and MUST NOT fall
back to deriving the comparison authority from `Host`.

### 7.8 OAuth 2.0 composition

ANS proves **who**; OAuth 2.0 grants **what**. A deployment adding OAuth presents the
DPoP-bound access token as `Authorization: DPoP <token>` (RFC 9449 §7.1), and RFC 9449 §4.3
requires two checks that deliberately land in different components:

| Check | Who runs it |
| --- | --- |
| `ath` equals `base64url(SHA-256(access token))` | The proof verifier (§7.4 step 8), automatically |
| The token's `cnf.jkt` confirmation claim equals the proof key's RFC 7638 thumbprint | **Whoever validates the token** — the token is opaque to the proof layer, and only its validator can read `cnf` |

The `ath` rule is strict in both directions: a proof carrying `ath` without a presented token is
rejected, and a presented token without a matching `ath` is rejected. A proof minted without a
token (the pure-ANS mode) carries no `ath`.

`ath` alone does not prove sender constraint — a thief holding the token can mint a fresh proof
with a matching `ath` under its own key — so the `cnf.jkt` comparison MUST be performed by the
token validator. When both the `Authorization` scheme parse and the `ath` verification read the
header, they MUST operate on identical bytes; a header value that parses differently for the two
checks is a rejection.

### 7.9 RFC 9449 conformance notes

- Proofs are wire-conformant RFC 9449 DPoP. ES256-only is a restriction
  [RFC 9449 §4.3](https://www.rfc-editor.org/rfc/rfc9449#section-4.3) permits; the closed header
  set (§7.2) and the absence of `x5c` chain validation (§7.5) are deviations from RFC 9449 §4.2 /
  [RFC 7515 §4, §4.1.6](https://www.rfc-editor.org/rfc/rfc7515#section-4), so an ANS-6 verifier
  rejects some RFC-conformant proofs.
- Server-provided nonces (RFC 9449 §8–§9) are not used; a callee MAY demand them by private
  agreement.

### 7.10 Outcomes

| Condition | Result |
| --- | --- |
| Duplicate `DPoP` / `Authorization` / SCITT header | Reject |
| Request authority outside the trusted set | Reject |
| Proof oversize, malformed, wrong `typ`/`alg`, extra header params, `d` in `jwk` | Reject |
| `ans_profile` malformed or unsupported | Reject |
| `x5c` count ≠ 1, non-P-256 leaf, certificate expired or not yet valid, `jwk` ≠ certificate key | Reject |
| Signature invalid | Reject |
| `htm`/`htu` mismatch | Reject |
| `ath` without token, token without `ath`, or hash mismatch | Reject |
| `ans_content_digest` absent, malformed, or mismatched, including a value other than the empty-content digest on a request without content | Reject |
| `iat` outside window; `jti` missing or oversize | Reject |
| Missing status token (or missing receipt where required) | Reject |
| Status token invalid, expired, or terminal status | Reject |
| Fingerprint not in `validIdentityCerts`; no/mismatched `ans://` URI SAN; receipt names a different agent | Reject |
| `jti` already seen; replay cache full or erroring | Reject (fail closed) |

### 7.11 Profile evolution

Payload claims are the extension lane: verifiers MUST ignore payload claims they do not understand
(§7.2), so an addition a verifier may safely ignore can be an OPTIONAL payload claim; a new
security requirement cannot rely on an older verifier enforcing a claim it ignores. A change a
verifier cannot safely ignore — a new `alg`, a different key-carriage mechanism, a tightened
check — is a profile revision, stated in the `ans_profile` claim (absence means revision 1), never
in `typ`. This document defines revision 1 only; selecting a later revision needs a verifiable
callee advertisement, which this revision does not define.

### 7.12 Request-content binding

The signed `ans_content_digest` binds request content, including its absence.

**Claim semantics.** The value is a JSON string containing `base64url(SHA-256(content))`,
using RFC 7515 §2 base64url encoding without padding. The input is the request content defined by
[RFC 9110 §6.4](https://www.rfc-editor.org/rfc/rfc9110#section-6.4): the octets after transfer
codings have been removed, with any content coding still applied. Chunk lengths, framing syntax,
and trailers are excluded; gzip-compressed content is hashed in its compressed form, before
content decoding. SHA-256 is pinned; algorithm changes require a profile revision (§7.11).

A signer MUST include `ans_content_digest` in every proof, regardless of HTTP method or whether
the request carries content. For no content, including a zero-length body, the value is the
digest of the empty octet string:
`47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU`.

**Verification is required for every proof:**

- Claim present and the digest of the received content does not match → reject.
- Claim present, request carries no content, and the value is not the empty-content digest →
  reject.
- Claim absent or malformed → reject.

Deployments MUST NOT transform request content on Method-B endpoints: re-encoding, recompression,
or other content changes invalidate the digest. Transfer framing may change if the content octets
remain unchanged.

**Verify before acting.** The digest MAY be computed incrementally as content streams, but the
callee MUST complete the comparison before committing the `jti` or acting on any of the content;
content-size bounding precedes hashing.

[RFC 9530](https://www.rfc-editor.org/rfc/rfc9530) `Content-Digest` MAY be emitted alongside
for diagnostics but MUST NOT be accepted in place of the claim: an unsigned header can be
rewritten by an intermediary. The computation matches RFC 9530's `sha-256` semantics.

## 8. Version changes and certificate rotation

### 8.1 Version changes

A version bump is a new registration under the same `agentHost`
([ANS-2 §2.3](ans-2-versioned-naming.md#23-supersession)): both versions are ACTIVE with
independent Identity Certificates, independent TL entries, and coexisting `_ans-badge` records.

- **Selecting the right badge**: select by the `version` field of the `_ans-badge` records. The
  caller's URI SAN names it (Method A); for a callee, prefer the version the caller intends or an
  `ACTIVE` record. The callee's status token `ansName` names the exact version served (§5.2).
- **SCITT artifacts are per-version**: each version has its own receipt (its own leaf) and its
  own status token (its own `ansName`). Certificate-fingerprint arrays absorb rotations *within*
  a version; version changes produce separate artifacts, never merged arrays.

### 8.2 Certificate rotation

Rotation ([ANS-1 §7](ans-1-registration.md#7-lifecycle-operations)) changes fingerprints without
changing `agentId`, ANSName, or DNS structure, so a verifier's cached view can go stale the
moment new certificates deploy:

- **SCITT tier**: no gap. The status token's `validIdentityCerts` / `validServerCerts` arrays
  carry old and new fingerprints through the overlap window; matching any entry suffices.
- **Badge tier**: on a fingerprint mismatch against a cached badge, force one refresh and
  re-compare before rejecting — the sealed event after rotation carries the updated arrays.
- **DANE**: during Server Certificate rotation both old and new TLSA records exist; §5.3's
  check-all-records rule covers it.

## 9. Failure handling

### 9.1 DNS lookup failure (badge tier)

Distinguish NXDOMAIN (record does not exist → not an ANS agent) from SERVFAIL/timeout (lookup
failed → apply failure policy). When some of several `_ans-badge` URLs fail to fetch, one
retrieved-and-matching badge suffices; none retrievable → failure policy.

NXDOMAIN can be the post-revocation state (revocation removes `_ans-badge`,
[ANS-1 §7](ans-1-registration.md#7-lifecycle-operations)), so when a peer presents an ANS Identity
Certificate and its host publishes no matching badge record, the answer is rejection (§6.2); a
cached pre-revocation badge is not a fallback.

### 9.2 TL unreachable (badge tier)

| Policy | Behavior | Trade-off |
| --- | --- | --- |
| Fail closed | Reject | Secure; reduces availability |
| Fail open with cache | Accept on a sufficiently fresh cached badge | Requires an explicit staleness threshold |
| Fail open | Accept unverified | NOT RECOMMENDED |

Badges and status tokens come from the same log, so a TL outage degrades both tiers once the
status-token TTL + skew (+ §9.4 grace) elapses; past that, the cached-badge row's staleness
threshold also bounds a growing revocation blind spot (§11.1). Deployments SHOULD treat the token
TTL as their TL-outage budget.

### 9.3 Receipt unavailable (SCITT tier)

A cached receipt remains valid (§4.3); a `503` from the receipt endpoint (checkpoint pending) is
retried per `Retry-After`. When no receipt is available at all: fall back to the badge tier, or
fail closed, per deployment policy.

### 9.4 Status token unavailable or expired (SCITT tier)

| Policy | Behavior | Trade-off |
| --- | --- | --- |
| Fall back to badge | Live TL status check | Reintroduces the online query |
| Grace window | Accept a recently-expired token within a bounded grace (e.g. ≤ 1× TTL) | Extends the revocation-latency bound by the grace |
| Fail closed | Reject | Secure; reduces availability |

### 9.5 Unknown signing key (SCITT tier)

A receipt or status token carrying a `kid` that matches no cached root key is not immediately a
forgery — the TL may have added a key (§4.5). Refresh `/root-keys` once, cooldown-gated, and
retry the lookup; if the `kid` is still unknown, reject. Do not fall back to a weaker tier on an
unknown `kid` alone.

### 9.6 Replay cache unavailable or saturated (Method B)

The replay cache fails closed per §7.6; there is no weaker tier to fall back to. Deployments
monitor occupancy against the §7.6 sizing.

### 9.7 Recommended fallback order

1. **Status token** — signature, `exp`, fingerprint arrays (offline).
2. **Cached receipt** — inclusion proof (offline; proves registration, not liveness — pair with
   whichever status source is available).
3. **Badge** — live TL query.
4. **Fail closed.**

Fallbacks apply to *missing or stale* evidence. Evidence that is present and fails — a bad Merkle
proof, a forged signature, a fingerprint mismatch, a terminal status — is a rejection, not a
trigger to try a weaker tier; a missing SCITT artifact on a `DPoP` request is likewise a rejection
(§7.10), not a fallback trigger.

## 10. Conformance

A conformant ANS-6 callee implements §4 and at least one caller-authentication method (§6 or §7),
documents which, and fails closed throughout. Method B is conformant only with its SCITT binding:
a callee that accepts DPoP proofs without verifying a status token against the proof certificate
(§7.5) is non-conformant. A conformant ANS-6 caller implements §4.6 and §5 and, under Method B,
§7.2 and §7.12.

A conformant implementation of either role passes the profile's conformance vectors. The vector
suite MUST include the §7.2 negative cases — a library-added `kid`, a multi-entry `x5c`, a
`jwk` carrying members beyond the four, a `d` in the `jwk` — and these payload cases:

- An unknown payload claim is ignored; an otherwise-valid proof still verifies.
- An absent `ans_profile` and an explicit `ans_profile: 1` both select revision 1; malformed
  values and unsupported revisions reject.
- A missing, malformed, or mismatched `ans_content_digest` rejects, including content added to
  an empty request or removed from a request with content.
- The empty-content digest verifies for an empty request; changing transfer framing alone
  preserves verification, and content codings remain applied when computing the digest (§7.12).

## 11. Security considerations

### 11.1 Revocation latency

Revocation is bounded, not instantaneous, and the bounds compose. On the SCITT tier the worst
case is status-token TTL + clock skew + grace: one hour by default
([ANS-4 §5.2](ans-4-transparency.md#52-receipts-status-tokens-checkpoints)), plus the §4.4 step 7
skew allowance (up to 10 minutes), plus §9.4's grace window (up to 1× TTL) — 2 hours 10 minutes
at the defaults. On the badge tier the bound is the badge cache TTL plus the §9.2 staleness
threshold, both deployment configuration rather than spec-bounded: a deployment MUST document the
values it runs, and SHOULD bound §4.6's verified-result reuse by the status-token TTL so "cached
for the life of the process" is unreachable. High-assurance deployments shorten the token TTL,
decline the §9.4 grace, or supplement critical transitions with live badge checks.

### 11.2 Leaf trust versus tree-head trust

A receipt authenticates the TL's signed leaf, not a tree head (§4.3); publication and consistency
checks use the signed checkpoint
([ANS-4 §5.2](ans-4-transparency.md#52-receipts-status-tokens-checkpoints)).

### 11.3 Hostile callee (Method B)

Callee authentication (§5) runs before the request body is sent: a misdirected Method-B request
leaks only public artifacts and one spent proof, but the body itself may be sensitive.

### 11.4 Root-key trust is fetch-channel trust

A new root key is trusted on no more evidence than a TLS fetch from a trusted TL domain (§4.5),
and cached keys are never removed. A compromised `/root-keys` endpoint can therefore introduce a
key that verifiers trust until operators intervene. The append-only contract keeps the damage
auditable — keys cannot be silently swapped, only added — the collision rule blocks `kid` reuse,
and the refresh cooldown bounds the fetch-amplification surface. Deployments needing more SHOULD
pin keys explicitly and treat any addition as an operator-approval event rather than an automatic
merge.

ANS-6 defines no in-band way to stop trusting a compromised TL key; distrusting one invalidates
every receipt and status token it signed, so retirement is a log-wide incident procedure that
belongs in ANS-4.

## Appendix A: Worked examples

Non-normative worked examples (`_ans-badge` record, receipt and status-token structures, root-key
line, a complete Method-B request/response exchange) live at
[`examples/ans-6-examples.md`](examples/ans-6-examples.md).

## 12. References

- ANS-1 [`ans-1-registration.md`](ans-1-registration.md): registration aggregate, lifecycle, rotation.
- ANS-2 [`ans-2-versioned-naming.md`](ans-2-versioned-naming.md): ANSName, Identity Certificate URI SAN, mTLS handshake shapes.
- ANS-3 [`ans-3-dns-publication.md`](ans-3-dns-publication.md): `_ans-badge` and TLSA family trust records.
- ANS-4 [`ans-4-transparency.md`](ans-4-transparency.md): TL public API, receipts, key distribution, checkpoint anchoring.
- ANS-5 [`ans-5-integrity-monitoring.md`](ans-5-integrity-monitoring.md): out-of-band verification checks and channels.
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449): OAuth 2.0 Demonstrating Proof of Possession (DPoP).
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515): JWS (`x5c` header, compact serialization).
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) / [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518): JWK and JWA (EC keys, ES256).
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519): JWT claims and handling of unrecognized claims.
- [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638): JWK thumbprint (`cnf.jkt`).
- [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162): Merkle tree hashing and inclusion proofs.
- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052): COSE (receipt and status-token envelopes).
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): JCS canonicalization (leaf bytes).
- [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698): DANE TLSA.
- [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125): TLS server-identity (hostname) verification (§5).
- [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530): HTTP content digests (digest semantics for §7.12; header form is diagnostic-only).
- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110): HTTP semantics (header fields, auth schemes).
- [C2SP signed-note](https://c2sp.org/signed-note): root-key line format.
