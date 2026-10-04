<?php
declare(strict_types=1);
/**
 * Composer loads this package through the PSR-4 map in composer.json: a class
 * or interface named KemProof\X is looked for in src/X.php, and nowhere else.
 * A user implements StoreInterface before constructing KemAttestation, so the
 * interface must be found on its own, first.
 *
 * This registers the same mapping Composer generates, read from composer.json,
 * so it needs neither Composer nor the network.
 */
$root = \dirname(__DIR__);
$map  = \json_decode((string) \file_get_contents($root . '/composer.json'), true)['autoload']['psr-4'] ?? [];
\spl_autoload_register(static function (string $name) use ($map, $root): void {
    foreach ($map as $prefix => $dir) {
        if (\strncmp($name, $prefix, \strlen($prefix)) === 0) {
            $file = $root . '/' . \rtrim($dir, '/') . '/' . \str_replace('\\', '/', \substr($name, \strlen($prefix))) . '.php';
            if (\is_file($file)) {
                require $file;
            }
        }
    }
});

$fail = 0;
// Order matters: the interface first, as a user implementing a store would.
foreach (['interface' => 'KemProof\StoreInterface', 'class' => 'KemProof\KemAttestation'] as $kind => $name) {
    $ok = $kind === 'interface' ? \interface_exists($name) : \class_exists($name);
    printf("  %-9s %-26s %s\n", $kind, $name, $ok ? 'found' : 'NOT FOUND');
    if (!$ok) { $fail++; }
}

// The other direction: a name the map does not provide must not be found.
if (\class_exists('KemProof\DoesNotExist')) {
    echo "  control: a missing class was found — the loader is not checking\n";
    $fail++;
}

echo $fail === 0 ? "\nautoload: every public name resolves through PSR-4\n" : "\n$fail name(s) do not resolve through PSR-4\n";
exit($fail === 0 ? 0 : 1);
