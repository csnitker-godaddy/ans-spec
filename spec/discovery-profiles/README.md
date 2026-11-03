# DNS discovery profiles

A discovery profile defines DNS records, labels, wire values, and required flags for a registration.
[ANS-3 §6](../ans-3-dns-publication.md#6-discovery-profiles) owns profile selection, defaults,
V1 compatibility, composition, and the authoritative registry. Required profile content is in
[§6.2](../ans-3-dns-publication.md#62-the-profile-template).

| Profile | Discovery records |
| --- | --- |
| [ANS_TXT](ans-txt.md) | `_ans` TXT records and an HTTPS RR |
| [ANS_DNSAID](ans-dnsaid.md) | SVCB records with DNS-AID parameters |

Both profiles include the [family trust records](../ans-3-dns-publication.md#63-family-trust-records).
The composed set follows the
[ordering, deduplication, and required-flag rules](../ans-3-dns-publication.md#64-composition-ordering-dedup-and-the-required-flag-transition)
and the [activation validations](../ans-3-dns-publication.md#4-activation-validations).

## Conformance artifacts

- [RA API](../../api/api-spec-v2.yaml): `DiscoveryProfile` and `discoveryProfiles` request schemas.
- [Record-set contract](../ans-3-dns-publication.md#3-record-set-and-child-label-structure).
- Exact record forms and worked examples in each profile.
