# ANS-2: Versioned Naming

Status: DRAFT v1.0
Spec: ANS-2 (Versioned Naming)
Version: 0.2.0
Date: 2026-07-15
Audience: implementers adding semantic-version naming and Identity Certificate binding to an ANS Registration Authority

## 1. Scope

Every registration has an ANSName ([ANS-1 §4.1](ans-1-registration.md#41-step-1--pending-registration)).
The Identity Certificate is optional ([ANS-1
§7.2](ans-1-registration.md#72-registrations-without-an-identity-certificate)); the URI SAN binding and
mTLS semantics below apply when it is present.

ANS-2 specifies:

- The ANSName URI form (`ans://v<MAJOR>.<MINOR>.<PATCH>.<host>`) and version-coexistence rules.
- The version field carried on emitted DNS records and Transparency Log events.
- The Identity Certificate URI SAN binding, including the CSR-side requirement.
- mTLS handshake semantics that consume the Identity Certificate.

## 2. The ANSName

`ans://v{version}.{agentHost}`

Example: `ans://v1.0.0.sentiment-analyzer.example.com`

Every registration declares a version, so every registration has an ANSName; the name is constructed at registration ([ANS-1 §4.1](ans-1-registration.md#41-step-1--pending-registration)) and is consumed **permanently** — uniqueness is checked against every registration regardless of status, so a FAILED, EXPIRED, or cancelled attempt still holds its version and a retry must use a new one.

| Component | Constraints | Example |
| --- | --- | --- |
| **protocol** | Fixed. Always `ans` | `ans` |
| **version** | Semantic version, numeric only: `major.minor.patch`. No pre-release or build-metadata suffixes. Prefixed with `v` | `v1.0.0` |
| **agentHost** | FQDN per RFC 1123. Each label is at most 63 octets, uses LDH characters (letters, digits, hyphens), and does not begin or end with a hyphen | `sentiment-analyzer.example.com` |

### 2.1 Length limits

`agentHost` MUST NOT exceed 253 octets (the RFC 1035 §2.3.4 domain-name limit) and MUST contain at
least two labels. The ANSName has no separate length cap; its bound is derived — the fixed
`ans://v` prefix, the version segment, and the host.

### 2.2 Registration metadata accompanying the ANSName

`agentDisplayName` and `agentDescription` ([ANS-1 §4.1](ans-1-registration.md#41-step-1--pending-registration))
accompany the ANSName at registration but are not part of the identifier. Display names need not be
unique; uniqueness is on the ANSName, and the FQDN is shared by every version registered under it.

### 2.3 Supersession

Versions are independent registrations: a version bump is a new registration under the same `agentHost` with a new `version` ([ANS-1 §7](ans-1-registration.md#7-lifecycle-operations)). Each version's `AGENT_REGISTERED` event carries the full ANSName.

A patch bump may coexist for hours; a major version change may coexist for months. ANS-2 does not impose a retirement timeline. If the new registration fails validation, the old version remains ACTIVE.

## 3. The Identity Certificate

When a registrant submits a `version` and `identityCsrPEM`, the RA's Private CA issues an Identity Certificate. The binding runs through both artifacts:

- **The CSR MUST carry the registration's full ANSName as a `uniformResourceIdentifier` SAN.** The RA validates the CSR's URI SAN against the expected ANSName before signing; a CSR naming any other identifier is rejected. (Server CSRs differ: they carry the agent's FQDN as a DNS SAN, the TLS server-auth convention.)
- **The issued certificate carries the same ANSName URI SAN**, with `digitalSignature` key usage and the `clientAuth` extended key usage, and a CA-configured validity window.

| Property | Value |
| --- | --- |
| Issuer | Private CA operated by the RA |
| SAN type | `uniformResourceIdentifier` |
| SAN value | The full ANSName (`ans://v{version}.{agentHost}`), validated against the CSR |
| Key usage | `digitalSignature`; EKU `clientAuth` |
| Purpose | Binds the certificate to a specific software version, presentable as a TLS client certificate |

Only the RA's Private CA can issue it: CA/B Forum Baseline Requirements §7.1.2.7.12 prohibit
`uniformResourceIdentifier` SANs in publicly trusted server certificates. Identity Certificates MUST
NOT be brought-your-own (a rogue CA could otherwise mint one the TL would seal as RA-validated); the
registration request accepts only a CSR.

## 4. mTLS with Identity Certificates

Identity Certificates are presented in the mTLS handshake; the handshake authenticates each party's
ANSName and step 6 confirms the sealed version. The handshake runs between agents; ANS components
issue and attest certificates but are not in the connection path.

### 4.1 Mutual TLS handshake

1. Caller sends `ClientHello`.
2. Server returns Server Certificate plus `CertificateRequest`.
3. Caller presents its Identity Certificate.
4. Server verifies the caller's Identity Certificate against the ANS Private CA's published trust anchor.
5. mTLS tunnel established. The caller knows the server's FQDN; the server knows the caller's ANSName.
6. Caller verifies the server's versioned identity via `_ans-badge` TXT record or TL query.

### 4.2 Handshake scenarios across registration shapes

Steps 3 and 4 require the party being authenticated to hold an Identity Certificate:

- **Identity-bearing callee, identity-bearing caller.** Standard mTLS; each party verifies the other's Identity Certificate against the ANS Private CA, and the caller verifies the server's fingerprint at step 6.
- **Server-Certificate-only callee, identity-bearing caller.** The callee verifies the caller's Identity Certificate; the callee authenticates via its Server Certificate and the caller verifies it at step 6.
- **Identity-bearing callee, Server-Certificate-only caller.** Step 5 establishes server-authenticated TLS rather than mTLS; the caller is anonymous at the TLS layer and MUST authenticate through application-layer means (API key, OAuth, delegation token).
- **Both Server-Certificate-only.** Server-authenticated TLS with no ANS Identity Certificate on either side; step 6 still runs on the callee.

DANE (`_443._tcp` TLSA) remains an optional additional pinning check across all scenarios.

The combination a callee presents is fixed at registration ([ANS-1
§7.2](ans-1-registration.md#72-registrations-without-an-identity-certificate)).

## 5. Conformance

A conformant ANS-2 implementation implements §§2–4.

## 6. References

- ANS-1 specification: [`ans-1-registration.md`](ans-1-registration.md). Registration aggregate, lifecycle.
- ANS-3 specification: [`ans-3-dns-publication.md`](ans-3-dns-publication.md). Per-version DNS records.
- ANS-4 specification: [`ans-4-transparency.md`](ans-4-transparency.md). Sealed events, badge endpoint.
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) URI generic syntax (`ans://` scheme validity).
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) X.509 (URI SANs, revocation).
- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) ACME (FQDN domain-control proof).
