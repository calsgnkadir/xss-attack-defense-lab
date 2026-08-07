// vulnerable-sanitizer.js
// EDUCATIONAL — a deliberately weak, blocklist-based HTML "sanitizer".
//
// It only thinks about <script> and the "javascript:" scheme. That is the classic
// mistake this lab's assessment exploited (see the report): blocking <script> does
// nothing against an *event-handler* vector such as <img src=x onerror=...>, which
// executes through a different code path. A single-pass blocklist is not protection.
//
// Do NOT use this for anything real. It exists to be broken.

function vulnerableSanitize(html) {
  return String(html)
    // strip <script>...</script> blocks (single pass)
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
    // strip the javascript: scheme
    .replace(/javascript:/gi, '');
  // NOTE: event-handler attributes (onerror, onload, onmouseover, ...) are NOT handled,
  // so <img src=x onerror=...> sails straight through.
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { vulnerableSanitize };
}
