// Example of safe equivalents. dxa should stay quiet here (or only flag the
// low-confidence constant case), because attacker input never reaches a sink.

// Safe: render user input as text, not HTML
const q = new URLSearchParams(location.search).get('q');
document.getElementById('out').textContent = q;

// Safe: build DOM nodes instead of parsing HTML
const el = document.createElement('span');
el.textContent = location.hash.slice(1);
document.body.appendChild(el);

// Safe: setTimeout with a function reference, not a string
setTimeout(function () { doWork(); }, 1000);

// Safe: navigation validated against an allowlist before use
const allowed = ['/home', '/profile'];
if (allowed.includes(next)) {
    location.href = next;
}
