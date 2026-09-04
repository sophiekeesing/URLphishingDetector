# DPIA Screening

A full Data Protection Impact Assessment (GDPR Art. 35) is required when
processing is "likely to result in a high risk" to individuals. This
screening records why URL Shield, as designed, does **not** meet that
threshold — and what would change that.

## Screening against the Art. 35(3) / EDPB criteria

| Criterion | Applies? | Notes |
| --- | --- | --- |
| Systematic and extensive evaluation / profiling | No | No profiling. No scoring of the person. Detection logic acts on the URL string only. |
| Automated decision-making with legal / significant effect | No | Output is an advisory warning; the user always decides. No page is blocked. |
| Systematic monitoring of a publicly accessible area | No (by default) | Default build is scan-on-demand. The optional "scan as I browse" mode is user-enabled, local-only by default, and does not record or transmit history. |
| Sensitive data or highly personal data | No | URLs only; no special categories processed intentionally. Query strings (which could carry such data) are stripped before any hashing or transmission. |
| Data processed on a large scale | Potentially, if widely distributed | Mitigated: transient local processing, no central collection, 4-byte-prefix k-anonymity for the only URL-derived data that leaves the device. |
| Matching / combining datasets | No | No enrichment, no cross-dataset linkage. |
| Data concerning vulnerable subjects | Not targeted | General-audience tool. |
| Innovative use of new technology | No | Heuristics + established Safe Browsing / DNS techniques. No ML model. |
| Prevents data subjects exercising a right / using a service | No | Warnings are dismissible; the tool can be disabled entirely. |

Two or more criteria met → do a DPIA. Here **zero to one** are met
depending on distribution scale, all with strong mitigations.

## Conclusion

A full DPIA is not mandatory for the current design. This screening
plus the [LIA](LIA.md) is retained as accountability evidence
(Art. 5(2)). 

## Triggers for a full DPIA

- Making any cloud lookup part of the no-consent default path.
- Persisting visited URLs or verdict history beyond the transient cache.
- Adding profiling, per-user risk scoring, or an ML model trained on or
  run against user browsing.
- Adding a threat-intel source that publishes or crowd-shares submitted
  URLs (e.g. VirusTotal, public urlscan.io).
- Central server-side collection of any URL-derived data.
