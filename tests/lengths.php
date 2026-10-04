<?php
declare(strict_types=1);
/**
 * attest() copies exactly SK_LEN bytes of the secret key and CT_LEN bytes of
 * the ciphertext into liboqs. Input of any other length must be refused
 * before that copy: a longer key would otherwise be cut silently and a
 * shorter one would surface as an FFI error instead of a clear one.
 *
 * No liboqs is needed: the length checks run before the library is loaded,
 * so a correct length reaches the "liboqs not available" error and a wrong
 * one never gets that far.
 */
require __DIR__ . '/../src/KemAttestation.php';

final class NullStore implements KemProof\StoreInterface
{
    public function put(string $subject, array $record): void {}
    public function get(string $subject): ?array { return null; }
}

$kem  = new KemProof\KemAttestation(__DIR__ . '/does-not-exist.so', new NullStore());
$fail = 0;

// [label, secret key length, ciphertext length, expected message fragment]
$cases = [
    ['sk ok, ct ok',       2400, 1088, 'liboqs not available'],
    ['sk 2401',            2401, 1088, 'secret key must be 2400 bytes'],
    ['sk 2399',            2399, 1088, 'secret key must be 2400 bytes'],
    ['sk empty',              0, 1088, 'secret key must be 2400 bytes'],
    ['ct 1089',            2400, 1089, 'ciphertext must be 1088 bytes'],
    ['ct 1087',            2400, 1087, 'ciphertext must be 1088 bytes'],
];

foreach ($cases as [$label, $skLen, $ctLen, $want]) {
    try {
        $kem->attest('example', 'sid', \str_repeat("\x01", $skLen), \str_repeat("\x02", $ctLen));
        $got = '(no exception)';
    } catch (\Throwable $e) {
        $got = \get_class($e) . ': ' . $e->getMessage();
    }
    $ok = \strpos($got, 'RuntimeException') === 0 && \strpos($got, $want) !== false;
    printf("  %-14s %s  %s\n", $label, $ok ? 'ok' : 'WRONG', $got);
    if (!$ok) { $fail++; }
}

echo $fail === 0 ? "\nlengths: every wrong length is refused before liboqs is touched\n" : "\n$fail length case(s) wrong\n";
exit($fail === 0 ? 0 : 1);
