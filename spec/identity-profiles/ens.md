# Identity profile: `ens`

Status: DRAFT v1.0
Profile: ens (Ethereum Name Service names)
Core: [ANS-0: Identity](../ans-0-identity-anchor.md)
Version: 0.1.0
Date: 2026-07-27
Audience: implementers building an ANS-conformant Registration Authority

An `ens` identity binds an ENS name to the Ethereum account that currently owns it. The
authoritative "key" is not published in a document; it is the **owner account** resolved from the
ENS registry hierarchy on-chain, and control is proven by an Ethereum account signature from that
owner (EIP-712 for EOAs, ERC-1271 for contract accounts such as Safes). Key-control axis only
([ANS-0 §3.1](../ans-0-identity-anchor.md#31-the-two-axes)); no location challenge.

## 1. Identifier form, canonicalization, selection

- **Form**: an ENS name under the `.eth` TLD, at any depth (e.g. `acme-corp.eth`,
  `agents.acme-corp.eth`, `eu.agents.acme-corp.eth`).
- **Selection**: **lexical** — a dot-separated name whose final label is `eth`. (Other TLDs
  reachable through the ENS root are not lexically distinguishable from plain FQDNs; admitting
  them is a future amendment of this profile's selection rule, not a change to the gate.)
- **Canonicalization** (each violation → `ENS_BAD_FORMAT`):
  - the name normalizes under [ENSIP-15](https://docs.ens.domains/ensip/15) (ENS Name
    Normalization); the canonical value is the normalized name;
  - the name has at least one label under `.eth` (the bare TLD is not a registrable identity).
- **Scope rule (mechanical)**: the name MUST resolve to a non-zero owner through the on-chain
  registry walk (§2). Names whose ENS presence is resolver-only — for example DNS domains
  resolved through ENS via DNSSEC-gated resolution — have **no on-chain owner**.
- **Derived encodings** (DNS wire format for contract calls, labelhashes) are derived from the
  canonical name as needed and are never part of the sealed identity evidence.

## 2. Control proof — key control, owner signature

The proof demonstrates possession of the key of the name's **current owner account**, bound to
this object and operation through the shared `IdentityProofInput` (ANS-0 §3.2). `verify-control`
checks, **in order** — every check clean before any seal:

1. **Envelope**: exactly one Ethereum-signature proof is present (this kind is single-key — the
   owner; there is no multi-key submission). A malformed envelope →
   `IDENTIFIER_PROOF_INVALID`.
2. **Signing input construction**: the RA builds the message to verify **solely from the served
   `signingInput`** — for EIP-712, as the `signingInput` field of the typed struct below; for
   EIP-191, as the signed message string. The client transmits only the signature (§10), so there
   is no client-supplied payload to compare and no separate payload-mismatch failure; a signature
   over anything other than the served input simply fails signature verification (check 4).
   Clients never canonicalize.
3. **Authoritative owner resolution** (verify time): the RA resolves the name's owner by the
   top-down registry walk — from the configured ENS root registry, descend one label at a time
   via `IRegistry.getSubregistry(label)` to the name's parent registry, confirm it supports
   `IOwnedRegistry` (ERC-165), and read `findOwner(label)`. The walk starts from the
   deployment-configured root, so no registrant-supplied registry or resolver address is ever
   consulted. A zero owner — never registered, reserved, expired, or resolver-only ENS presence —
   → `ENS_NAME_UNOWNED`. When the name's own parent registry is still reachable, the RA MAY
   refine a lapsed leaf to `ENS_NAME_EXPIRED` via that registry's `findExpiry(label)`; an expired
   *ancestor* instead zeroes the walk higher up, leaving no registry to query, so it stays
   `ENS_NAME_UNOWNED`. Advisory resolution at challenge time seeds the challenge entry;
   the verify-time resolution is binding.
4. **Signature verification** against the resolved owner:
   - **EOA**: recover the signer per **EIP-712** (preferred) or EIP-191 and require it to equal
     the resolved owner.
   - **Contract account**: **ERC-1271** `isValidSignature(hash, signature)` via `eth_call`
     against the owner contract — the path by which multisig and smart-account owners (e.g.
     Safes) prove control.
   - The signer MUST be the owner itself. Holders of EAC roles on the name and ERC-1155-approved
     operators are **delegates**, not the owner, and are NOT acceptable signers. Failure →
     `ENS_SIGNATURE_INVALID`.
5. **Nonce**: unexpired, unconsumed, consumed by the successful call only (ANS-0 §3.2 token
   discipline).

**EIP-712 binding.** The typed-data encoding is a thin wrapper that carries the served signing
input as its only field, so payload equality (check 2) stays a byte comparison:

```text
EIP712Domain { name: "ans:identity-proof", version: "1", chainId: <configured chain> }
IdentityProof { string signingInput }
```

`chainId` binds the proof to the deployment's configured network (one deployment = one chain,
mirroring `raId`).

## 3. Key source and selection

The one authoritative key-holder is the name's **current owner account**, resolved from the ENS
registry hierarchy at verify time (§2 check 3) — never presented in the request. This kind is
single-key; there is no JWS `kid` selector (the one signer is fully determined by the
identifier, as with `lei`). The challenge entry advisorily names the resolved owner as a CAIP-10
account (`eip155:<chain>:<address>`, the address in EIP-55 checksummed form) so the client can
confirm which account must sign.

## 4. Seal tier — verbatim verification method

The sealed verification method is the resolved owner account as a CAIP-10 `blockchainAccountId`,
sealed as resolved — the same account-based `blockchainAccountId` seal the
[`did:ethr`](did-ethr.md) profile uses — alongside the submitted signature. The address component
of the `blockchainAccountId` is the **EIP-55 checksummed** form, so a given owner yields one
canonical account string across RAs. Address equality during verification (EOA recovery,
ERC-1271) is compared on the 20-byte value; the string that is sealed and advertised is always
the EIP-55 form.

```json
{
  "id": "ens:acme-corp.eth#owner",
  "type": "EcdsaSecp256k1RecoveryMethod2020",
  "controller": "ens:acme-corp.eth",
  "blockchainAccountId": "eip155:1:0x1234…abcd"
}
```

Registry state — records, expiry, roles, resolver configuration — is **referenced, never copied**
into the seal. An **EOA** proof re-verifies offline by signature recovery against the sealed
`blockchainAccountId`. A **contract-account** proof (ERC-1271) was verified by the RA at proof time
against then-current chain state; a third party re-checking via `eth_call` reads *current* state, so
a later change to the account's signer set can make the re-check differ — that is a drift signal
(§5), not evidence the original proof was invalid.

## 5. Freshness and monitoring

ANS-5 monitors an `ens` identity as a first-class object on its own per-identity cadence
([ANS-5 §4.2](../ans-5-integrity-monitoring.md#42-verified-identity-monitoring)). Because ENS
token IDs are mutable (regenerated on role changes), monitors MUST key on the **name** and re-read
state, never track token IDs. Signals, from one state re-read per cycle:

- **Owner change**: re-run the §2 owner resolution; sealed account ≠ current owner is the
  integrity signal. ENS names are transferable assets, so an owner change is a continuity
  event: surfaced as a finding, never an automatic revocation. Lifecycle handling follows §6 —
  same-provider re-proof, or revoke-and-re-register when the controlling party changes.
- **Expiry**: read the name's `findExpiry(label)` on its parent registry. Approaching expiry is an
  advisory finding; after expiry the owner resolves to zero. A name that lapses and is
  re-registered by a different party is an owner change handled per §6.
- **Optional cross-attestation**: an [ENSIP-26](https://docs.ens.domains/ensip/26)
  `agent-endpoint[ans]` text record on the name, naming a linked agent's ANSName in URI form
  (`ans://…`) — a public,
  name-side declaration that complements the sealed link (the ANS-5 principal-binding check
  set includes it).

## 6. Lifecycle specifics

- **Owner change within the same provider (rotation).** When the controlling account moves
  between wallets of the **same** `providerId`, the identifier's value survives, so this is a
  value-stable rotation: the new controlling account re-proves via `PUT` + `verify-control`,
  sealing `IDENTITY_UPDATED`, and the audit stream preserves the owner succession.
- **Transfer to a different party.** When the name moves to an account controlled by a
  **different** party, `PUT` rotation does not apply: identity routes are owner-scoped to the
  `providerId` (ANS-0 §7) and one `(kind, value)` is `VERIFIED` by at most one owner (ANS-0 §11).
  The outgoing party **revokes** the identity (`POST …/revoke`; revoke is credential-gated to the
  `providerId`, ANS-0 §6) and the acquirer registers the name as a new identity under their own
  `providerId`. Until the outgoing party revokes, the value stays bound to their now-stale
  identity; the ANS-5 owner-change finding surfaces this, but the identity layer does not
  auto-remediate it.
- **Revocation**: `POST …/revoke`; read-side terminality keeps it revoked (ANS-0 §8.3).
- **Re-proof after nonce expiry**: idempotent re-add (ANS-0 §5).

## 7. Outbound-fetch safety

The verification I/O is **chain reads only**: the registry walk (pure `view` calls — the
canonical navigation contracts perform no CCIP-Read) and, for contract accounts, one ERC-1271
`eth_call`. All reads go through **configured, pinned JSON-RPC endpoints** — never
registrant-supplied URLs — with bounded call budgets, and RPC failures surface as a generic
retryable error (`ENS_CHAIN_UNAVAILABLE`) that never echoes endpoint details (no oracle).

An ERC-3668 `OffchainLookup` revert on any control-path `eth_call` (the registry walk and any
ERC-1271 verification) MUST be treated as a hard failure (`ENS_OFFCHAIN_LOOKUP_BLOCKED`) and MUST
NOT trigger an offchain request.

A deployment that additionally reads ENS *records* (the §5 ENSIP-26 cross-check) may traverse
wildcard/offchain resolution (CCIP-Read), which **is** registrant-steered and MUST be hardened
exactly like the did:web fetcher (ANS-0 §13).

## 8. Error codes

| Code | Meaning |
| --- | --- |
| `ENS_BAD_FORMAT` | not ENSIP-15-normalizable, not a `.eth` name, or the bare `.eth` TLD (no label under it) |
| `ENS_NAME_UNOWNED` | the registry walk resolves no current owner (never registered, reserved, expired, or resolver-only ENS presence) |
| `ENS_NAME_EXPIRED` | refinement of `ENS_NAME_UNOWNED` when the parent registry's expiry shows a lapsed registration |
| `ENS_SIGNATURE_INVALID` | signature fails validation against the resolved owner, or the signer is not the owner (role holders and operators are rejected); an owner contract that reverts or returns a non-affirming value under ERC-1271 is treated as invalid |
| `ENS_CHAIN_UNAVAILABLE` | a chain read failed at the transport level (RPC error or timeout); retryable; no endpoint detail echoed |
| `ENS_OFFCHAIN_LOOKUP_BLOCKED` | a control-path call attempted an ERC-3668 offchain lookup; non-retryable (§7) |
| `IDENTIFIER_KIND_UNSUPPORTED` | returned while the profile is Postponed (no verifier enabled) |

(Generic identity codes — `IDENTIFIER_KIND_UNSUPPORTED`, `IDENTIFIER_DUPLICATE`,
`IDENTIFIER_CHALLENGE_EXPIRED`, `IDENTIFIER_PROOF_INVALID`, `TL_UNAVAILABLE`,
`VERIFICATION_IN_FLIGHT`, … — are defined in ANS-0 / the API spec.)

## 9. Status and requirement

**Requirement: Optional** ([ANS-0 §12.2](../ans-0-identity-anchor.md#122-optional-capability-verified-identities)).

**Status: Postponed (design of record).** The flow above is settled and its external surface is
live (the ENS registry hierarchy, `UniversalResolverV2.findOwner`, and the universal
signature-validation interface are deployed); the kind is disabled until an ENS owner-resolver
and an Ethereum-signature verifier are implemented and tested, returning
`IDENTIFIER_KIND_UNSUPPORTED` until then.

## 10. Object schemas (postponed shapes)

Postponed shapes: the design of record, not frozen wire, and not covered by
[`api/identity-event-schema-v2.json`](../../api/identity-event-schema-v2.json).

**Register** — `POST /v2/ans/identities` with the bare identifier:

```json
{ "value": "acme-corp.eth" }
```

**Challenge round** — the `202` response (single entry; the advisory `kid` names the resolved
owner as a CAIP-10 account):

```json
{
  "identityId": "0193f0c5-7b2e-7a41-9c3d-bbbbbbbbbbbb",
  "kind": "ens",
  "value": "acme-corp.eth",
  "status": "PENDING_CONTROL",
  "nonce": "<base64url 32-byte single-use nonce>",
  "expiresAt": "2026-07-27T19:30:00Z",
  "challenges": [
    {
      "kid": "eip155:1:0x1234…abcd",
      "signingInput": "<base64url(JCS({identifier, identityId, nonce, purpose, raId, scheme}))>"
    }
  ]
}
```

**verify-control (postponed, non-JOSE)** — one Ethereum signature over the served signing input
from the name's current owner (`encoding` names the framing; contract-account signatures use the
same envelope and are validated via ERC-1271):

```json
{ "ethSignature": { "encoding": "eip712", "signature": "0x<65-byte signature hex>" } }
```

**Sealed proven key (postponed)** — the proof event records the derived CAIP-10 account method
(§4) plus the submitted signature:

```json
{
  "verificationMethod": {
    "id": "ens:acme-corp.eth#owner",
    "type": "EcdsaSecp256k1RecoveryMethod2020",
    "controller": "ens:acme-corp.eth",
    "blockchainAccountId": "eip155:1:0x1234…abcd"
  },
  "signedProof": "0x<65-byte signature hex>",
  "proofEncoding": "eip712"
}
```
