# Legitimate Interest Assessment (LIA)

Covers both the **local, on-device** checks and the **network lookups**,
which are now enabled by default rather than consent-gated.

The change of basis for the network lookups (from Art. 6(1)(a) consent
to Art. 6(1)(f) legitimate interest) was deliberate: a security tool
whose protection is off until the user finds a settings page protects
almost nobody, and the users most at risk are the least likely to go
looking. Recital 49 names network and information security explicitly
as a legitimate interest.

The safeguards that make this defensible, and which must not be removed:

- the options page opens on first install, so the user sees what is
  running before they browse;
- every lookup has an individual opt-out plus a single "turn everything
  off" control (right to object, Art. 21);
- with them off, the extension still works — nothing leaves the device;
- the data minimisation below is what keeps the intrusion low enough for
  the balance to hold.

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
| Reasonable expectations | A user installing a phishing checker expects it to read the address of the page being checked, and expects it to work without being configured first. |
| Intrusiveness | Low. Local checks: on-device, transient, no history, no profiling. Network lookups: 4-byte hash prefixes to Safe Browsing, hostname only to the resolvers, registrable domain only to the registry — never the full URL, never the query string. |
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
