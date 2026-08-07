// secure-sanitizer.js
// EDUCATIONAL — the defensive counterpart to vulnerable-sanitizer.js.
//
// Two correct approaches are shown:
//   1) safeText()        — output ENCODING. If you only need text, never build HTML.
//                          The browser escapes everything; nothing can execute. Safest.
//   2) allowlistSanitize()— an ALLOWLIST parser. Parse the input into an inert DOM,
//                          keep ONLY known-safe tags/attributes, drop everything else,
//                          then re-serialise. Event handlers, <img>, <script>, iframe,
//                          and javascript: URLs are all removed because they are not on
//                          the allowlist — not because we tried to blacklist them.
//
// In production, prefer a battle-tested library (DOMPurify) instead of hand-rolling.
// This is written out so the *mechanism* is visible.

// 1) Output encoding — the simplest safe render.
function safeText(input) {
  const el = document.createElement('div');
  el.textContent = String(input); // browser escapes < > & " automatically
  return el.innerHTML;            // e.g. <img ...> becomes &lt;img ...&gt; (inert text)
}

// 2) Allowlist sanitiser.
const ALLOWED_TAGS = new Set(['B', 'I', 'EM', 'STRONG', 'P', 'BR', 'CODE', 'A', 'UL', 'OL', 'LI']);
const ALLOWED_ATTR = { A: new Set(['href']) };
const SAFE_URL = /^(https?:|mailto:|\/|#)/i; // no javascript:, data:, etc.

function allowlistSanitize(html) {
  const tpl = document.createElement('template');
  tpl.innerHTML = String(html); // <template> content is inert — nothing runs here

  const clean = (node) => {
    for (const child of [...node.childNodes]) {
      if (child.nodeType === Node.ELEMENT_NODE) {
        if (!ALLOWED_TAGS.has(child.tagName)) {
          // drop the tag but keep its (recursively cleaned) text
          child.replaceWith(document.createTextNode(child.textContent));
          continue;
        }
        const allowed = ALLOWED_ATTR[child.tagName] || new Set();
        for (const attr of [...child.attributes]) {
          const name = attr.name.toLowerCase();
          const badHref = name === 'href' && !SAFE_URL.test(attr.value.trim());
          if (!allowed.has(name) || badHref) child.removeAttribute(attr.name);
        }
        clean(child); // recurse
      } else if (child.nodeType !== Node.TEXT_NODE) {
        child.remove(); // comments, etc.
      }
    }
  };
  clean(tpl.content);
  return tpl.innerHTML;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { safeText, allowlistSanitize };
}
