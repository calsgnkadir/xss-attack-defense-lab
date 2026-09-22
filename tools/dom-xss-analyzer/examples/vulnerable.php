<?php
// Example file demonstrating what dxa flags on PHP. Every pattern below is
// intentionally unsafe and is for detector testing only.

// HIGH: superglobal source flows straight into echo (unescaped output)
$q = $_GET['q'];
echo "You searched: " . $q;

// HIGH: direct source-in-same-line echo (no taint hop needed)
echo "Direct: " . $_GET['direct'];

// HIGH: taint propagates through a variable, then hits print
$name = $_POST['name'];
$greet = "Hello " . $name;
print $greet;

// HIGH: <?= short-echo of a superglobal value
?>
<p>Search: <?= $_REQUEST['keyword'] ?></p>
<?php

// HIGH: server header (HTTP_USER_AGENT etc.) echoed unescaped
$ua = $_SERVER['HTTP_USER_AGENT'];
echo "<div>Your UA: $ua</div>";

// HIGH: Laravel Blade raw output ({{ }} escapes; {!! !!} does not)
// {!! $comment !!}      // (blade pseudo-line, kept as a string for the linter)
echo "{!! " . $comment . " !!}";

// MEDIUM: printf on a dynamic format string
printf($tmpl, $x);

// MEDIUM: Twig |raw filter defeats auto-escaping
$rendered = $twig->render("<p>{{ body|raw }}</p>");
