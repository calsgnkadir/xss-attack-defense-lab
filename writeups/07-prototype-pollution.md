# Prototype Pollution: poisoning every object at once

> **TL;DR** — In JavaScript almost every object inherits from
> `Object.prototype`. If an attacker can write **one** property onto that shared
> prototype — usually via a `__proto__` key that a recursive merge or query-string
> parser copies without checking — that property appears on **every object in the
> program**. On its own that's just a weird global; but when a **gadget** (app code
> that reads a normally-absent property and passes it to a sink) picks it up, the
> pollution becomes XSS. Two ingredients: a guardless write, and a sink that reads
> the polluted value.

The other writeups here inject into *one* value and reach *one* sink. Prototype
pollution is different in blast radius: you don't target a specific object, you
poison the **base class** every object inherits from, then let the application's own
code carry the payload the rest of the way.

## The one idea: `__proto__` writes to the shared parent

`obj.__proto__` is a reference to `Object.prototype` — the object every plain
object inherits from. So writing through it changes *all* objects:

```js
const a = {}, b = {};
a.__proto__.polluted = "yes";
b.polluted            // → "yes"   (b never asked for it)
({}).polluted         // → "yes"   (brand-new object, already poisoned)
```

Attackers rarely write `a.__proto__.x` literally. They find code that copies
**attacker-controlled keys** into an object without guarding `__proto__`:

```js
// vulnerable recursive merge
function merge(dst, src) {
  for (const k in src) {
    if (typeof src[k] === 'object') merge(dst[k] ??= {}, src[k]);
    else dst[k] = src[k];              // no check for k === '__proto__'
  }
}
merge({}, JSON.parse('{"__proto__":{"polluted":"yes"}}'));   // pollutes Object.prototype
```

The same happens in query-string parsers that expand bracket notation:
`?__proto__[polluted]=yes` becomes `obj['__proto__']['polluted'] = 'yes'`.

## Turning pollution into XSS: the gadget

Pollution alone changes behaviour; to get script execution you need a **gadget** —
existing code that reads a property which is *normally undefined on the object* and
sends it to a dangerous sink. Because the object doesn't have the property, the
lookup falls through to the **polluted prototype**, and your value is returned:

```js
// gadget in the app
const opts = getUserOptions();                 // {} — no `template` key
element.innerHTML = opts.template || defaultTemplate;
```

If you pollute `Object.prototype.template` with `<img src=x onerror=alert(1)>`,
then `opts.template` (absent on `opts`) resolves to your payload → it reaches
`innerHTML` → XSS. The local lab
[`labs/protopollution-lab.html`](../labs/protopollution-lab.html) chains exactly
this: `?__proto__[x]=…` in the URL pollutes the prototype, and a gadget then reads
`x` into an `innerHTML` sink. It's **Finding #11**.

This is a real-world class, not a toy: **jQuery `$.extend(true, …)` before 3.4**
(CVE-2019-11358) and older **Lodash `_.merge`** were both pollutable, so any app
bundling them inherited the sink.

## Why it's easy to miss

- **The write and the sink are far apart.** The pollution happens in a generic
  utility (a merge, a config loader); the XSS fires in unrelated rendering code.
  Neither looks wrong on its own.
- **`__proto__` is invisible in a normal object dump.** `console.log(obj)` won't
  show the inherited property unless you look up the chain.
- **It survives across requests/objects.** Once `Object.prototype` is polluted,
  every object created afterwards carries the payload.

## The fix

1. **Guard the dangerous keys.** In any merge/parse that takes user keys, reject
   `__proto__`, `constructor`, and `prototype`.
2. **Use prototype-less containers.** `Object.create(null)` (or a `Map`) for
   user-keyed data — there is no prototype to poison, and `Map` doesn't confuse
   keys with object properties at all.
3. **`Object.freeze(Object.prototype)`** as defense in depth — a frozen prototype
   can't be written to.
4. **Keep libraries current.** jQuery ≥ 3.5, patched Lodash; audit dependencies
   for known pollution CVEs.
5. **Kill the gadget too.** Don't read `x || fallback` off attacker-influenced
   objects straight into `innerHTML`; sanitise/validate at the sink regardless.

## Takeaway

Prototype pollution is a **one-write, program-wide** bug: a single `__proto__` key
that a careless merge accepts poisons the parent of every object, and a gadget the
app already ships turns that into an `innerHTML` XSS. Guard `__proto__` at the
write, use `Object.create(null)`/`Map` for user data, and don't let a
fall-through property reach a sink.

---

*Demonstrated on authorized targets only:
[`labs/protopollution-lab.html`](../labs/protopollution-lab.html) (Finding #11) and
the client-side prototype-pollution lab on PortSwigger's Web Security Academy —
`?__proto__[x]=…` → gadget → `innerHTML`. Same repo discipline (`source → sink`)
with the twist that the "source" writes to a shared prototype.*
