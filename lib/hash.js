// ---------------------------------------------------------------------
// hash.js — SHA-256 helpers for the k-anonymity lookup
// ---------------------------------------------------------------------
// The extension computes a full SHA-256 of each URL expression locally,
// but only ever transmits the first 4 bytes (the "hash prefix"). The
// server returns every full hash that starts with those 4 bytes; the
// exact match is finished here, on the device. The server therefore
// never learns which URL was checked (Google Safe Browsing model).
//
// Note: a hash is pseudonymisation, not anonymisation — GDPR still
// applies. The privacy gain is the truncation + local matching, not
// the hashing itself.
// ---------------------------------------------------------------------

const PREFIX_BYTES = 4;

async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

// For each expression: its full-hash (base64, for local matching) and
// its 4-byte prefix (base64, the only thing sent over the network).
export async function hashExpressions(expressions) {
  const out = [];
  for (const expr of expressions) {
    const full = await sha256(expr);
    out.push({
      expression: expr,
      fullHashB64: bytesToBase64(full),
      prefixB64: bytesToBase64(full.slice(0, PREFIX_BYTES)),
    });
  }
  return out;
}
