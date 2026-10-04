<?php
declare(strict_types=1);
/**
 * A reference verifier endpoint for client/attest.py — small on purpose.
 *
 *   GET  .../handshake?subject=S   -> {session_id, public_key}
 *   POST .../attest                -> the stored record, or an error
 *
 * Try it:
 *   KEMPROOF_LIBOQS=/path/to/liboqs.so KEMPROOF_DATA=/var/lib/kemproof \
 *     php -d ffi.enable=true -S 127.0.0.1:8080 examples/verifier.php
 *
 * Outside the CLI, PHP's default ffi.enable=preload forbids loading liboqs at
 * run time: set ffi.enable=true for this pool, or preload the library.
 *   python3 client/attest.py http://127.0.0.1:8080 my-subject /path/to/liboqs.so
 *
 * What it does that a careless endpoint would not:
 * - the secret key never leaves the server; it is kept under the session id
 *   with the subject named at handshake time;
 * - a session is single-use: it is deleted before attest() runs, so the same
 *   exchange cannot be replayed to refresh a record, and a failed attempt
 *   cannot be retried against the same keypair;
 * - sessions not used within SESSION_TTL seconds are refused;
 * - an attestation must name the same subject as its handshake.
 *
 * Not production code: no rate limit, no authentication of who may attest a
 * subject. Those depend on your estate.
 */
require __DIR__ . '/../src/KemAttestation.php';

use KemProof\KemAttestation;
use KemProof\StoreInterface;

const SESSION_TTL = 300;

final class FileStore implements StoreInterface
{
    private string $dir;
    public function __construct(string $dir) { $this->dir = $dir; }
    private function path(string $subject): string
    {
        return $this->dir . '/' . \hash('sha256', $subject) . '.json';
    }
    public function put(string $subject, array $record): void
    {
        $tmp = $this->path($subject) . '.' . \bin2hex(\random_bytes(4));
        if (\file_put_contents($tmp, \json_encode($record), \LOCK_EX) === false
            || !\rename($tmp, $this->path($subject))) {
            throw new RuntimeException('record could not be stored');
        }
    }
    public function get(string $subject): ?array
    {
        $path = $this->path($subject);
        if (!\file_exists($path)) {
            return null; // never attested
        }
        // Present but unreadable is a failure, not "never attested".
        $raw = \file_get_contents($path);
        $record = $raw === false ? null : \json_decode($raw, true);
        if (!\is_array($record)) {
            throw new RuntimeException('record for this subject exists but cannot be read');
        }
        return $record;
    }
}

function reply(int $status, array $body): void
{
    \http_response_code($status);
    \header('Content-Type: application/json');
    echo \json_encode($body);
}

$lib  = (string) \getenv('KEMPROOF_LIBOQS');
$data = (string) \getenv('KEMPROOF_DATA');
if ($lib === '' || $data === '' || !\is_dir($data) || !\is_writable($data)) {
    reply(500, ['error' => 'KEMPROOF_LIBOQS and a writable KEMPROOF_DATA are required']);
    return;
}
foreach (["$data/sessions", "$data/records"] as $d) {
    if (!\is_dir($d) && !\mkdir($d, 0700) && !\is_dir($d)) {
        reply(500, ['error' => "cannot create $d"]);
        return;
    }
}

$kem   = new KemAttestation($lib, new FileStore("$data/records"));
$route = \basename((string) \parse_url($_SERVER['REQUEST_URI'] ?? '', \PHP_URL_PATH));

try {
    if ($route === 'handshake' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        $subject = (string) ($_GET['subject'] ?? '');
        if ($subject === '') {
            reply(400, ['error' => 'subject is required']);
            return;
        }
        $hs = $kem->handshake();
        $session = "$data/sessions/{$hs['session_id']}";
        $old = \umask(0077);
        $written = \file_put_contents($session, \json_encode([
            'subject'    => $subject,
            'created_at' => \time(),
            'secret_key' => \base64_encode($hs['secret_key']),
        ]), \LOCK_EX);
        \umask($old);
        if ($written === false) {
            reply(500, ['error' => 'session could not be stored']);
            return;
        }
        reply(200, ['session_id' => $hs['session_id'], 'public_key' => \base64_encode($hs['public_key'])]);
        return;
    }

    if ($route === 'attest' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $in  = \json_decode((string) \file_get_contents('php://input'), true);
        $sid = \is_array($in) ? (string) ($in['session_id'] ?? '') : '';
        if (!\preg_match('/^[0-9a-f]{32}$/', $sid)) {
            reply(400, ['error' => 'session_id must be 32 hex characters']);
            return;
        }
        // Claim the session by renaming it: of two concurrent requests only
        // one rename succeeds. The other sees no session, as after a use.
        $session = "$data/sessions/$sid";
        $claimed = "$session.used." . \bin2hex(\random_bytes(4));
        if (!\file_exists($session)) {
            reply(404, ['error' => 'unknown or already used session']);
            return;
        }
        if (!@\rename($session, $claimed)) {
            // Gone in between: another request claimed it. Still there: the
            // rename failed for another reason, and that is not a 404.
            \file_exists($session)
                ? reply(500, ['error' => 'session could not be claimed'])
                : reply(404, ['error' => 'unknown or already used session']);
            return;
        }
        $s = \json_decode((string) \file_get_contents($claimed), true);
        \unlink($claimed);

        if (\time() - (int) $s['created_at'] > SESSION_TTL) {
            reply(410, ['error' => 'session expired']);
            return;
        }
        if (($in['subject'] ?? null) !== $s['subject']) {
            reply(400, ['error' => 'subject differs from the one named at handshake']);
            return;
        }
        $ct = \base64_decode((string) ($in['ciphertext'] ?? ''), true);
        $cf = \base64_decode((string) ($in['confirmation'] ?? ''), true);
        if ($ct === false || $cf === false) {
            reply(400, ['error' => 'ciphertext and confirmation must be base64']);
            return;
        }
        $record = $kem->attest($s['subject'], $sid, \base64_decode($s['secret_key']), $ct, $cf);
        reply(200, $record);
        return;
    }

    reply(404, ['error' => 'routes: GET handshake, POST attest']);
} catch (RuntimeException $e) {
    $m = $e->getMessage();
    // 403: the prover was not confirmed. 400: the input was malformed.
    // 500: anything else is ours (liboqs, storage), not the prover's.
    $status = \strpos($m, 'key confirmation failed') === 0 ? 403
        : (\preg_match('/^(ciphertext|confirmation) must be /', $m) ? 400 : 500);
    reply($status, ['error' => $m]);
} catch (\Throwable $e) {
    // Never a stack trace to the prover: it names paths on this server.
    \error_log('kemproof verifier: ' . $e);
    reply(500, ['error' => 'internal error']);
}
