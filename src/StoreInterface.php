<?php
declare(strict_types=1);

namespace KemProof;

/** Where attestations live. Bring your own: a table, a file, a cache. */
interface StoreInterface
{
    public function put(string $subject, array $record): void;

    /** @return array<string,mixed>|null null when the subject was never attested */
    public function get(string $subject): ?array;
}
