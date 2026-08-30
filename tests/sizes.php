<?php
declare(strict_types=1);
/**
 * The constants in KemAttestation must match ML-KEM-768 as specified in
 * NIST FIPS 203. Wrong sizes would not throw: they would silently produce a
 * fingerprint of the wrong bytes, and the record would still look valid.
 */
require __DIR__ . '/../src/KemAttestation.php';

$expected = ['PK_LEN' => 1184, 'SK_LEN' => 2400, 'CT_LEN' => 1088, 'SS_LEN' => 32];
$r = new ReflectionClass(KemProof\KemAttestation::class);
$fail = 0;

foreach ($expected as $name => $want) {
    $got = $r->getConstant($name);
    $ok  = ($got === $want);
    printf("  %-8s expected %-5d got %-5s  %s\n", $name, $want, var_export($got, true), $ok ? 'ok' : 'MISMATCH');
    if (!$ok) { $fail++; }
}

if ($r->getConstant('ALG') !== 'ML-KEM-768') {
    printf("  %-8s expected %-5s got %s  MISMATCH\n", 'ALG', 'ML-KEM-768', var_export($r->getConstant('ALG'), true));
    $fail++;
} else {
    printf("  %-8s %-30s ok\n", 'ALG', 'ML-KEM-768');
}

// The other direction: a wrong value must be rejected, not tolerated.
if ($r->getConstant('CT_LEN') === 1087) {
    echo "  control: a wrong size would have passed — the check is not checking\n";
    $fail++;
}

echo $fail === 0
    ? "\nsizes match NIST FIPS 203 for ML-KEM-768\n"
    : "\n$fail constant(s) do not match FIPS 203\n";
exit($fail === 0 ? 0 : 1);
