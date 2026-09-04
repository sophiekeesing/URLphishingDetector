# Legitimate Interest Assessment (LIA)

For the **local, on-device** URL checks that run without consent.
Cloud lookups do not rely on this basis — they run on consent
(GDPR Art. 6(1)(a)).

## 1. Purpose test — is there a legitimate interest?

Yes. Protecting users from phishing and malware is network and
information security processing, which Recital 49 GDPR names explicitly
as a legitimate interest. The interest is the user's own security and,
derivatively, the maintainer's interest in providing an effective tool.

## 2. Necessity test — is the processing necessary?

Yes, and it is minimal:

- only the URL of the page the user actively asks to check is processed;
- processing is in memory, on the device; results are held for at most
  10 minutes to avoid recomputation;
- no less-intrusive method achieves the same warning (the check
  inherently needs the URL).

## 3. Balancing test — does the interest override the user's rights?

| Factor | Assessment |
| --- | --- |
| Nature of data | A URL, which can be an online identifier (Art. 4(1)); treated as personal data. |
| Reasonable expectations | A user installing a phishing checker expects it to read the address of the page being checked. |
| Intrusiveness | Low: local only, transient, no history, no profiling, no transmission. |
| Power balance | User is in control: the check runs only on their action; the whole feature set can be disabled or the extension removed. |
| Safeguards | Data minimisation, no persistence beyond a short cache, no third-party disclosure, no telemetry, open source for scrutiny. |
| Risk to the individual | Negligible — data does not leave the device. |

**Conclusion:** the legitimate interest is not overridden by the
data subject's interests or fundamental rights. Legitimate interest is
an appropriate basis for the local checks. Cloud features remain
consent-based and off by default.

## Review

Re-assess on any change that (a) makes a network call part of the
default path, (b) adds persistence of URLs, or (c) introduces
profiling/ML on user data.
