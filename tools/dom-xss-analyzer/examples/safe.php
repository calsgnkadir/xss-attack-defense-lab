<?php
// Escaped/safe equivalents of the vulnerable.php patterns. dxa may still flag
// some lines at MEDIUM/LOW because the regex heuristic doesn't know about
// htmlspecialchars(), but none should reach HIGH confidence.

// Escaped output - the right way
$q = $_GET['q'];
echo "You searched: " . htmlspecialchars($q, ENT_QUOTES, 'UTF-8');

// Constant string - no attacker data at all
echo "static welcome message";

// Escaped in a short-echo tag
?>
<p>Search: <?= htmlspecialchars($_REQUEST['keyword'], ENT_QUOTES, 'UTF-8') ?></p>
<?php

// Blade safe form is {{ }}, not {!! !!}
// {{ $comment }}    // (pseudo-line for the linter)
echo "{{ escaped comment }}";
