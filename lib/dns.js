// ---------------------------------------------------------------------
// dns.js — minimal DNS-over-HTTPS client (RFC 8484 wireformat)
// ---------------------------------------------------------------------
// Cloudflare and Google offer a convenient JSON interface
// (?name=x&type=A), but Quad9 does not — dns.quad9.net answers such a
// request with "DoH unable to decode BASE64-URL". Only the standard
// wireformat works everywhere, so that is what we speak: the query is a
// binary DNS message, base64url-encoded into the ?dns= parameter.
//
// We do not need to decode answer records — only the 12-byte response
// header, which carries the response code and the answer count. That is
// enough to tell "resolved fine" from "the resolver refused it".
// ---------------------------------------------------------------------

export const RCODE_NOERROR = 0;
export const RCODE_NXDOMAIN = 3;

const MAX_LABEL = 63;
const MAX_NAME = 253;

// Build a DNS query message asking for the A record of `hostname`.
function encodeQuery(hostname) {
  const labels = hostname.split(".").filter(Boolean);
  if (!labels.length || hostname.length > MAX_NAME) return null;
  if (labels.some((l) => l.length > MAX_LABEL || !/^[a-z0-9_-]+$/i.test(l))) return null;

  const qnameLen = labels.reduce((n, l) => n + 1 + l.length, 0) + 1;
  const buf = new Uint8Array(12 + qnameLen + 4);
  const view = new DataView(buf.buffer);

  // Header. RFC 8484 recommends ID 0 so responses stay cacheable.
  view.setUint16(0, 0); // ID
  view.setUint16(2, 0x0100); // flags: recursion desired
  view.setUint16(4, 1); // one question

  let off = 12;
  for (const label of labels) {
    buf[off++] = label.length;
    for (let i = 0; i < label.length; i++) buf[off++] = label.charCodeAt(i);
  }
  buf[off++] = 0; // root label
  view.setUint16(off, 1); // QTYPE = A
  view.setUint16(off + 2, 1); // QCLASS = IN
  return buf;
}

function base64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Read just the header: { rcode, answers }.
function decodeHeader(arrayBuffer) {
  if (arrayBuffer.byteLength < 12) return null;
  const view = new DataView(arrayBuffer);
  return {
    rcode: view.getUint16(2) & 0x0f,
    answers: view.getUint16(6),
  };
}

// Query one DoH resolver. Throws on transport or protocol failure so
// the caller can distinguish "unavailable" from "answered".
export async function resolve(endpoint, hostname, { timeoutMs = 6000 } = {}) {
  const query = encodeQuery(hostname);
  if (!query) throw new Error("unencodable hostname");

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${endpoint}?dns=${base64url(query)}`, {
      headers: { Accept: "application/dns-message" },
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const header = decodeHeader(await res.arrayBuffer());
    if (!header) throw new Error("short DNS response");
    return header;
  } finally {
    clearTimeout(timer);
  }
}

// The resolver found real records for the name.
export function resolved({ rcode, answers }) {
  return rcode === RCODE_NOERROR && answers > 0;
}

// The resolver declined to answer: either NXDOMAIN, or NOERROR with no
// records at all. Filtering resolvers use both to signal a block.
export function refused({ rcode, answers }) {
  return rcode === RCODE_NXDOMAIN || (rcode === RCODE_NOERROR && answers === 0);
}
