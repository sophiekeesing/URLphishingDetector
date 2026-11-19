// ---------------------------------------------------------------------
// browser.js — one name for the extension API in every browser
// ---------------------------------------------------------------------
// Firefox calls it `browser`, Chrome and Edge call it `chrome`. Firefox
// also provides `chrome` as an alias, but `browser` is its native one, so
// prefer it when it exists.
//
// Outside an extension (the popup opened as a plain file) this is
// undefined or a page-level `chrome` object without `runtime`, so callers
// check for the part they need before using it.
// ---------------------------------------------------------------------

export const api = globalThis.browser ?? globalThis.chrome;
