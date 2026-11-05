# ANS-5: Integrity Monitoring (AIM)

Status: DRAFT v1.0
Spec: ANS-5 (Integrity Monitoring)
Version: 0.1.0
Date: 2026-05-17
Audience: implementers building or operating the Agent Integrity Monitor (AIM) and verifiers consuming its records

## 1. Scope

ANS-5 specifies periodic integrity checks of registered facts and the resulting verification records.

ANS-5 specifies:

- The verification-result contract: for a registration, produce attributable per-check results and evidence.
- The verification check set: which facts the AIM verifies, what passes, what fails.
- The verification procedure: the cryptographic-verification-path checks a verifier runs to confirm an agent.
- The integrity-reporting principles: monitors report, the RA acts; reports are public and signed; quorum before action; evidence MUST be verifiable.
- The transient-vs-mismatch distinction the AIM MUST observe.
- The principal-binding verification procedures for DID_WEB, LEI, BIOMETRIC_HASH, ENS_ENSIP25, and ENS_ENSIP26 binding types.

The AIM derives expected DNS state from the registration's discovery profiles
([ANS-3 §6](ans-3-dns-publication.md#6-discovery-profiles)) and runs the same checks regardless of
anchor or discovery profile. Verified Identities
([ANS-0 §4](ans-0-identity-anchor.md#4-the-verified-identity-object)) are monitored on their own
per-identity cadence (§4.2).

ANS-5 does **not**:

- Score, rank, or filter agents (trust scoring is outside ANS). A conforming AIM MAY be composed
  into a larger system that also performs scoring, provided the scoring function does not
  influence verification outcomes.
- Issue revocations or command state changes. Findings are reports; the RA decides what to do with them.
- Define which bindings are acceptable when.

## 2. Terminology

- **AIM (Agent Integrity Monitor)**: the service performing integrity checks. Monitoring MUST operate independently of the RA's request path; findings reach consumers through an implementation-defined integration.
- **Verification record**: the typed result of one verification cycle for one registration. Carries per-check outcomes, an evidence pointer, and a timestamp.
- **Evidence pointer**: an inline bundle or content-addressed reference to the network captures, certificate samples, DNS query traces, and external resolution responses the AIM gathered while verifying.
- **Finding**: a verification record where one or more checks failed. Findings are surfaced per the integrity-reporting principles (§6).
- **Mismatch vs. unreachable**: `Mismatch` means the content has changed (remediation needed); `Unreachable` means a transient network failure (retry later). Conflating the two would let a network glitch trigger suppression of a legitimate agent.

## 3. Verification results

An AIM MUST evaluate only `ACTIVE` registrations, perform the applicable checks in §4, and produce
results identifying the verification cycle, registration, per-check outcome, evidence, and timestamp.
Inapplicable checks MUST be omitted rather than reported as failures. Results MAY be grouped or
emitted individually if each carries the required provenance. Wire format and delivery mechanism
are implementation-defined.

## 4. Verification checks

The AIM verifies each ACTIVE registration independently.

| Check | What the AIM does | Pass condition | Required when |
| --- | --- | --- | --- |
| **TL presence** | Query the ANS-4 TL for the registration's most recent sealed event | Inclusion proof verifies against the TL's Signed Tree Head | Always |
| **DNS pointer** | Authoritative DNS query for the records emitted per ANS-3, with DNSSEC validation when the zone is signed | Records exist, content matches TL-sealed expected values, and DNSSEC validates (when signed) | Always (against the record set the registration's discovery profiles emit, [ANS-3 §6](ans-3-dns-publication.md#6-discovery-profiles)) |
| **Server Certificate match** | TLS handshake to the operational endpoint, extract certificate fingerprint | Fingerprint matches the value sealed in the TL | When the anchor profile ties to TLS (FQDN; `did:web` resolved domain) |
| **Identity Certificate match** | Verify identity certificate fingerprint against TL-sealed value (see §4 note below) | Fingerprint matches | Only when ANS-2 versioned registration |
| **Schema integrity** | Fetch each endpoint's `metaDataUrl`, hash the document | Hash matches the protocol-keyed entry in the TL `attestations.metadataHashes` map (e.g. `metadataHashes["A2A"]`) | Only when per-endpoint `metaDataHash` values were submitted at registration |
| **Principal binding (ENS_ENSIP25)** | Resolve ENS name; verify `agent-registration[<registry>][<tokenId>]` text record; verify ERC-8004 registration file lists the ENS name | Both directions agree | Only when `principalBinding.type` is `ENS_ENSIP25` |
| **Principal binding (ENS_ENSIP26)** | Resolve the ENS name from the agent's principal binding; verify its `agent-endpoint[ans]` text record (ENSIP-26) names one of the agent's ANSNames in URI form (`ans://…`) | Record matches the ANSName of an ACTIVE version of the agent | Only when `principalBinding.type` is `ENS_ENSIP26` |
| **Principal binding (DID_WEB)** | Fetch `/.well-known/did.json` from the declared domain | DID document exists with a valid verification method | Only when `principalBinding.type` is `DID_WEB` |
| **Principal binding (LEI)** | Verify vLEI credential signature against the issuing entity's registered key (Option A) or against the LOU's custom field signature (Option B) per the [lei profile](identity-profiles/lei.md) | Signature valid and LEI ACTIVE in GLEIF database | Only when `principalBinding.type` is `LEI` |
| **Principal binding (BIOMETRIC_HASH)** | Verify the biometric credential against the declared verifier's public key. The raw biometric data is never transmitted; only a hash or zero-knowledge proof | Credential verifies and matches the registered binding | Only when `principalBinding.type` is `BIOMETRIC_HASH` |
| **On-chain identity (ERC-8004)** | Verify agentId ownership on the Identity Registry, check Reputation Registry for active feedback | Owner address matches `principalBinding.identifier` | Only when `onChainId` references an ERC-8004 registration |

**DNS pointer record types.** `_ans` and `_ans-badge` (or `_ra-badge`) TXT records MUST be verified. TLSA and HTTPS/SVCB records SHOULD be verified when the registration's attestation includes them.

**DNS pointer content matching.** "Records exist and validate" means: (1) the record exists at the authoritative nameserver, (2) its content matches the TL-sealed expected value, and (3) the record's DNSSEC validation state is secure when the zone is signed. A record that exists but whose content does not match the sealed value is a `Mismatch` finding.

**Identity certificate verification note.** Runtime re-verification of the identity-certificate
fingerprint requires a presentation protocol ANS does not define; implementations SHOULD record the
certificate type as evidence and treat this check as deferred.

### 4.1 Check severity

An AIM MAY classify checks as verdict-determining (contribute to FAIL) or evidence-only and MUST
document which. An aggregate PASS/FAIL verdict is not trust scoring.

### 4.2 Verified-identity monitoring

This section applies only to the optional
[Verified Identity capability](ans-0-identity-anchor.md#122-optional-capability-verified-identities).
Each identity is monitored on its own cadence.

The per-identity check is **sealed-vs-live key drift**: the AIM re-resolves the identifier
through its [identity profile](identity-profiles/)'s key source (re-fetch the `did:web` document,
re-resolve the LEI's KEL key state, etc.) and compares the live authoritative key set against the
`keys[]` the latest sealed `IDENTITY_VERIFIED`/`IDENTITY_UPDATED` event recorded. A sealed key no
longer published, an unreachable document, or a key rotation that abandons the proven key is a
finding. `did:key` cannot drift (the key is the identifier) so its only monitored transition is
revocation.

Read-side revocation terminality ([ANS-0 §8.3](ans-0-identity-anchor.md#83-read-side-revocation-terminality)) is independent of monitoring — a revoked identity stays revoked on the public surface regardless of what a later probe sees.

## 5. Verification procedure (verifier-facing)

A verifier checks an agent through independent steps, each using a different trust channel.

| Step | Check | Trust channel | What it proves |
| --- | --- | --- | --- |
| 1 | PKI certificate validation | CA system | Standard TLS. Cannot detect a compromised CA |
| 2 | DANE record validation (FQDN anchors) | DNS (DNSSEC) | The Server Certificate fingerprint matches the TLSA record at `_{port}._tcp.{agentHost}` for the endpoint's port ([ANS-3 §6.3](ans-3-dns-publication.md#63-family-trust-records)). A compromised CA alone cannot forge this record (TLSA parameters and the DNSSEC prerequisite: [ANS-3 §6.3](ans-3-dns-publication.md#63-family-trust-records), [ANS-6 §5.3](ans-6-agent-authentication.md#53-danetlsa-optional-both-tiers)) |
| 3 | TL inclusion proof verification | TL (signed by a trusted TL key distributed through `/root-keys`) | The inclusion proof confirms the registration was sealed into the log. A tampered or deleted entry breaks the proof |
| 4 | Live state match | DNS + TLS | The current DNS records and certificates match what was sealed |

## 6. Integrity reporting principles

The AIM is external to the RA. Principles:

| Principle | Rule |
| --- | --- |
| **Monitors report, the RA acts** | External monitors publish findings. They cannot command state changes. The RA compares each finding against what the TL records before acting |
| **Reports SHOULD be signed** | Monitors SHOULD publish findings to cryptographically signed feeds, building a verifiable reputation |
| **Quorum before action** | The RA MUST NOT act on an unconfirmed finding. Quorum MAY be satisfied by corroboration from independent monitors, internal re-verification, or other confirmation mechanisms |
| **Evidence MUST be verifiable** | Every finding MUST include cryptographic proof of the discrepancy. The RA re-verifies independently before sealing an `INTEGRITY_WARNING` |

The AIM MUST make findings and evidence available through an implementation-defined integration. A
confirmed finding is advisory: the agent stays `ACTIVE`, and any suppression is a consumer policy
choice, not a registry state change.

## 7. Conformance

A conformant ANS-5 implementation implements §3–§6 and produces verification results meeting §3 for
any combination of ANS-0 anchor profile and ANS-3 DNS profile. A conforming verifier MUST NOT
reject a `VerificationRecord` because the AIM omitted an unavailable check.

**Conformance levels.** Implementations declare their conformance level:

- **Level 1 (Core)**: DNS pointer verification with content matching, DNSSEC chain validation, Server Certificate fingerprint match, and the Mismatch/Unreachable distinction. This is the minimum for a conforming implementation.
- **Level 2 (Extended)**: Level 1 plus Schema integrity and TL inclusion proof cryptographic verification.
- **Level 3 (Full)**: Level 2 plus all applicable principal-binding checks and On-chain identity. Level 3 requires protocol extensions not universally deployed; implementations declare which Level 3 checks they support.

## 8. Security considerations

### 8.1 Evidence-pointer integrity

The evidence bundle the AIM links to is itself subject to tampering. Verifiers consuming `INTEGRITY_WARNING` events and seeking to inspect evidence SHOULD verify the evidence bundle's signature against the AIM's published key before
relying on its contents.

## Appendix A: Worked examples

Non-normative worked example (AIM finding payload) lives at [`examples/ans-5-examples.md`](examples/ans-5-examples.md).

## 9. References

- ANS-0 specification: [`ans-0-identity-anchor.md`](ans-0-identity-anchor.md). The proof-of-control gate, the Verified Identity object and its monitoring, the [identity profiles](identity-profiles/).
- ANS-1 specification: [`ans-1-registration.md`](ans-1-registration.md). Registration aggregate, lifecycle, event set.
- ANS-3 specification: [`ans-3-dns-publication.md`](ans-3-dns-publication.md). Expected DNS records.
- ANS-4 specification: [`ans-4-transparency.md`](ans-4-transparency.md). TL receipts.
- [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698): DANE TLSA records.
- [ISO 17442](https://www.iso.org/standard/78829.html): Legal Entity Identifier (LEI).
