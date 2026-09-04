// ---------------------------------------------------------------------
// rdap.js — how old is this domain?
// ---------------------------------------------------------------------
// Domain age is one of the strongest phishing signals there is. Scam
// domains are registered days or weeks before a campaign because they
// get blocked quickly; the brands they imitate are decades old
// (instagram.com: 2004). Crucially this works on brands that are NOT in
// brands.js, which is where the local engine otherwise runs out.
//
// RDAP is the IETF replacement for WHOIS: free, keyless, JSON.
//
// We deliberately do NOT use the rdap.org bootstrap service, because it
// answers with a 302 to the registry's own server — and a redirect to a
// host the extension has no permission for simply fails. Instead the
// TLD -> endpoint map below is baked in, so every request goes straight
// to the right registry with no redirect, and the host permissions in
// manifest.json line up exactly with the endpoints listed here.
//
// Coverage is partial by design. TLDs absent from this map (and the
// many ccTLDs with no public RDAP at all — .de, .io, .co, .ru, .lv …)
// are reported as "not available" and contribute NO score either way.
// A missing answer is never treated as suspicious.
// ---------------------------------------------------------------------

// Endpoint bases, from IANA's RDAP bootstrap registry (data.iana.org).
// The TLD is a path segment for several registries, hence the {tld}
// placeholder rather than one fixed base per host.
const RDAP_ENDPOINTS = {
  com: "https://rdap.verisign.com/com/v1/",
  net: "https://rdap.verisign.com/net/v1/",
  cc: "https://tld-rdap.verisign.com/cc/v1/",
  org: "https://rdap.publicinterestregistry.org/rdap/",
  info: "https://rdap.identitydigital.services/rdap/",
  life: "https://rdap.identitydigital.services/rdap/",
  live: "https://rdap.identitydigital.services/rdap/",
  xyz: "https://rdap.centralnic.com/xyz/",
  icu: "https://rdap.centralnic.com/icu/",
  cyou: "https://rdap.centralnic.com/cyou/",
  sbs: "https://rdap.centralnic.com/sbs/",
  cfd: "https://rdap.centralnic.com/cfd/",
  monster: "https://rdap.centralnic.com/monster/",
  quest: "https://rdap.centralnic.com/quest/",
  top: "https://rdap.zdnsgtld.com/top/",
  online: "https://rdap.radix.host/rdap/",
  site: "https://rdap.radix.host/rdap/",
  store: "https://rdap.radix.host/rdap/",
  fun: "https://rdap.radix.host/rdap/",
  pw: "https://rdap.radix.host/rdap/",
  shop: "https://rdap.gmoregistry.net/rdap/",
  app: "https://pubapi.registry.google/rdap/",
  dev: "https://pubapi.registry.google/rdap/",
  zip: "https://pubapi.registry.google/rdap/",
  mov: "https://pubapi.registry.google/rdap/",
  uk: "https://rdap.nominet.uk/uk/",
};

// Every distinct origin above — used for the optional host permission
// request so the two can never drift apart.
export const RDAP_ORIGINS = [
  ...new Set(Object.values(RDAP_ENDPOINTS).map((u) => new URL(u).origin + "/*")),
];

export function rdapSupports(registrable) {
  const tld = registrable.split(".").pop();
  return Object.prototype.hasOwnProperty.call(RDAP_ENDPOINTS, tld);
}

const FETCH_TIMEOUT_MS = 7000;

// Returns { ageDays, registeredAt } — or null when the registry has no
// RDAP service, doesn't know the domain, or is unreachable.
export async function lookupDomainAge(registrable) {
  const tld = registrable.split(".").pop();
  const base = RDAP_ENDPOINTS[tld];
  if (!base) return null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(`${base}domain/${encodeURIComponent(registrable)}`, {
      headers: { Accept: "application/rdap+json" },
      signal: controller.signal,
    });
    // 404 means "no such registration" — common for a domain that only
    // exists as a subdomain of something else. Not a threat signal.
    if (!res.ok) return null;

    const data = await res.json();
    const event = (data.events || []).find((e) => e.eventAction === "registration");
    if (!event?.eventDate) return null;

    const registeredAt = new Date(event.eventDate);
    if (Number.isNaN(registeredAt.getTime())) return null;

    const ageDays = Math.floor((Date.now() - registeredAt.getTime()) / 86_400_000);
    if (ageDays < 0) return null; // clock skew / bad data
    return { ageDays, registeredAt: registeredAt.toISOString().slice(0, 10) };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// Turn an age into a weighted signal. Young domains add risk; a domain
// that has existed for years earns a small credit, which verdict.js
// discards if the address is impersonating a brand (attackers do buy
// aged domains, so age must never excuse a look-alike).
export function scoreDomainAge({ ageDays, registeredAt }) {
  const on = ` (registered ${registeredAt})`;
  if (ageDays < 7) {
    return {
      id: "domainAgeNewborn",
      weight: 42,
      message: `This domain was registered ${ageDays} day${ageDays === 1 ? "" : "s"} ago${on}. Almost every phishing site is days old — real companies' addresses are years old.`,
    };
  }
  if (ageDays < 30) {
    return {
      id: "domainAgeVeryNew",
      weight: 32,
      message: `This domain is only ${ageDays} days old${on}, which is typical of a scam site set up for a short campaign.`,
    };
  }
  if (ageDays < 90) {
    return {
      id: "domainAgeNew",
      weight: 20,
      message: `This domain is less than three months old${on} — young enough to be worth caution.`,
    };
  }
  if (ageDays < 180) {
    return {
      id: "domainAgeYoung",
      weight: 10,
      message: `This domain is under six months old${on}.`,
    };
  }
  if (ageDays >= 730) {
    return {
      id: "domainAgeEstablished",
      weight: -12,
      credit: true,
      message: `This domain has existed for over ${Math.floor(ageDays / 365)} years${on}, which counts in its favour.`,
    };
  }
  return null;
}
