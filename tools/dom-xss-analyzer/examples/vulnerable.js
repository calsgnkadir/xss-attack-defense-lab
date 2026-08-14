// Example file demonstrating what dxa flags. Every pattern below is intentionally
// unsafe and is for detector testing only.

// HIGH: attacker-controlled source flows straight into an HTML sink
const q = new URLSearchParams(location.search).get('q');
document.getElementById('out').innerHTML = q;

// HIGH: taint propagates through a variable, then hits a sink
let raw = location.hash.slice(1);
let msg = 'Hello ' + raw;
document.write(msg);

// HIGH: postMessage data reaching a sink (source only counts because a
// message listener is registered in this file)
window.addEventListener('message', function (e) {
    document.querySelector('#log').innerHTML = e.data;
});

// HIGH: code-execution sink fed by a source
eval(document.referrer);

// HIGH: Angular escaping deliberately bypassed
this.trusted = this.sanitizer.bypassSecurityTrustHtml(userInput);

// MEDIUM: jQuery HTML sink with a dynamic (non-literal) value
$('#name').html(userName);

// MEDIUM: navigation sink - a javascript: URL in `next` would execute
location.href = next;

// LOW: constant string sink (no dynamic input) - reported at low confidence
document.getElementById('static').innerHTML = '<b>welcome</b>';
