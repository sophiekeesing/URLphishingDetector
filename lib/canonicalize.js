// ---------------------------------------------------------------------
// canonicalize.js — turn a URL into privacy-safe lookup expressions
// ---------------------------------------------------------------------
// Data minimisation (GDPR Art. 5(1)(c)):
//   • the query string and fragment are DROPPED — they are where
//     session tokens, user IDs and emails live, and we never want them
//     hashed, cached, or sent anywhere;
//   • only host + path are kept, then expanded into the host/path
//     combinations Google Safe Browsing defines, so we can look up a
//     parent domain or folder without revealing the exact page.
//
// This is a deliberately reduced version of the Safe Browsing
// canonicalisation spec. Known simplifications: no repeated
// percent-unescaping loop, no IP-format normalisation, no special
// handling of multi-level public suffixes (e.g. .co.uk). Good enough
// for a warning tool; a production build should follow the full spec.
// ---------------------------------------------------------------------

function stripDots(host) {
  return host.replace(/^\.+/, "").replace(/\.+$/, "").replace(/\.{2,}/g, ".");
}

function normalisePath(pathname) {
  if (!pathname || pathname === "") return "/";
  const parts = [];
  for (const segment of pathname.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") parts.pop();
    else parts.push(segment);
  }
  const trailingSlash = pathname.endsWith("/") ? "/" : "";
  return "/" + parts.join("/") + (parts.length ? trailingSlash : "");
}

// Candidate hostnames: the exact host plus up to four parent domains,
// always keeping at least the final two labels.
function hostCandidates(host) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return [host];
  const labels = host.split(".");
  const out = [host];
  for (let i = 1; i <= 4 && labels.length - i >= 2; i++) {
    out.push(labels.slice(i).join("."));
  }
  return [...new Set(out)];
}

// Candidate paths: the exact path plus each parent folder, up to five.
function pathCandidates(path) {
  const out = ["/"];
  const segments = path.split("/").filter(Boolean);
  let acc = "";
  for (let i = 0; i < segments.length && i < 4; i++) {
    acc += "/" + segments[i];
    out.push(acc + "/");
  }
  if (path !== "/") out.push(path);
  return [...new Set(out)];
}

// Returns { hostname, expressions[] }. `expressions` are the strings to
// hash — host+path only, never the query.
export function canonicalize(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;

  const host = stripDots(u.hostname.toLowerCase());
  const path = normalisePath(u.pathname);
  if (!host) return null;

  const expressions = [];
  for (const h of hostCandidates(host)) {
    for (const p of pathCandidates(path)) {
      expressions.push(h + p);
    }
  }
  return { hostname: host, expressions: [...new Set(expressions)] };
}
