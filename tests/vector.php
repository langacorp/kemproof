<?php
declare(strict_types=1);
/**
 * Key confirmation test vectors. The same bytes are pinned in
 * tests/test_client.py: if the PHP verifier and the Python client ever build
 * the transcript differently, one of the two files fails, without liboqs.
 *
 * The values were computed separately by each implementation and found equal
 * before being written down here.
 */
require __DIR__ . '/../src/KemAttestation.php';

use KemProof\KemAttestation as K;

$fail = 0;
function check(string $label, bool $ok): void
{
    global $fail;
    printf("  %-58s %s\n", $label, $ok ? 'ok' : 'FAIL');
    if (!$ok) { $fail++; }
}

$v1 = K::confirmation(\str_repeat("\x11", 32), '00112233445566778899aabbccddeeff',
    'host.example.com', \str_repeat("\x22", 1184), \str_repeat("\x33", 1088));
check('vector 1: sizes of a real exchange',
    \bin2hex($v1) === 'a503bfca6f98b5237001f69dba4e03ca50366c519aecc81d606c89b2eff05353');

$v2 = K::confirmation(\str_repeat("\x11", 32), 's', 'caffè', '', '');
check('vector 2: non-ASCII subject, empty key and ciphertext',
    \bin2hex($v2) === '20b13d38c82d5fe4edd0035c13432c757e3de6a32c2d5056ebb8dbad0ba7a865');

// The other direction: every field is in the transcript. Change any one of
// them and the value must change.
$base = [\str_repeat("\x11", 32), 'sid', 'subject', 'pk', 'ct'];
$ref  = K::confirmation(...$base);
foreach (['shared secret', 'session id', 'subject', 'public key', 'ciphertext'] as $i => $name) {
    $args = $base;
    $args[$i] .= 'x';
    check("changing the $name changes the confirmation", K::confirmation(...$args) !== $ref);
}
// Length prefixes: moving a byte from one field to the next is a different transcript.
check('moving a byte between subject and session id changes it',
    K::confirmation(\str_repeat("\x11", 32), 'ab', 'c', 'pk', 'ct')
    !== K::confirmation(\str_repeat("\x11", 32), 'a', 'bc', 'pk', 'ct'));

echo $fail === 0 ? "\nvector: the confirmation is pinned and binds every field\n" : "\n$fail vector check(s) failed\n";
exit($fail === 0 ? 0 : 1);
