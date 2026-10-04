"""
Tests for client/attest.py. Standard library only, no network: a local
http.server thread plays the verifier.

The real ML-KEM-768 tests need liboqs and run only when KEMPROOF_LIBOQS points
to the shared library. Without it they are reported as skipped, not passed.
"""
import base64
import ctypes
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import unittest
from urllib.parse import parse_qs, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "client"))
import attest as client  # noqa: E402

LIBOQS = os.environ.get("KEMPROOF_LIBOQS", "")


class FakeVerifier(http.server.BaseHTTPRequestHandler):
    """Records what the client sent. Hands out a public key of the right size."""
    seen = {}
    handshake_status = 200

    def log_message(self, *args):
        pass

    def _reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlsplit(self.path)
        type(self).seen["handshake_path"] = url.path
        type(self).seen["handshake_subject"] = parse_qs(url.query).get("subject")
        self._reply(type(self).handshake_status, {
            "session_id": "00" * 16,
            "public_key": base64.b64encode(b"\x01" * client.PK_LEN).decode(),
        })

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen["attest_path"] = urlsplit(self.path).path
        type(self).seen["attest_body"] = body
        self._reply(200, {"subject": body["subject"], "valid": True})


class ClientProtocolTest(unittest.TestCase):
    """The HTTP side of the client, with encapsulation replaced by a stub."""

    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), FakeVerifier)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d/kem/v1/" % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        FakeVerifier.seen = {}
        FakeVerifier.handshake_status = 200
        self._load, self._encapsulate = client.load, client.encapsulate
        self.public_keys = []
        client.load = lambda path: None

        def fake_encapsulate(lib, public_key):
            self.public_keys.append(public_key)
            return b"\x02" * client.CT_LEN, b"\x05" * client.SS_LEN
        client.encapsulate = fake_encapsulate

    def tearDown(self):
        client.load, client.encapsulate = self._load, self._encapsulate

    def test_plain_subject_round_trip(self):
        record = client.attest(self.base, "host-1.example.com", "unused")
        self.assertEqual(record, {"subject": "host-1.example.com", "valid": True})
        seen = FakeVerifier.seen
        self.assertEqual(seen["handshake_path"], "/kem/v1/handshake")
        self.assertEqual(seen["attest_path"], "/kem/v1/attest")
        self.assertEqual(seen["handshake_subject"], ["host-1.example.com"])
        body = seen["attest_body"]
        self.assertEqual(body["subject"], "host-1.example.com")
        self.assertEqual(body["session_id"], "00" * 16)
        self.assertEqual(base64.b64decode(body["ciphertext"]), b"\x02" * client.CT_LEN)
        self.assertEqual(self.public_keys, [b"\x01" * client.PK_LEN])
        self.assertEqual(base64.b64decode(body["confirmation"]), client.confirmation(
            b"\x05" * client.SS_LEN, "00" * 16, "host-1.example.com",
            b"\x01" * client.PK_LEN, b"\x02" * client.CT_LEN))

    def test_subject_reaches_handshake_unchanged(self):
        # The handshake must name the same subject the attestation is for.
        for subject in ["a&subject=b", "with space", "caffè", "x#y", "50%"]:
            with self.subTest(subject=subject):
                FakeVerifier.seen = {}
                client.attest(self.base, subject, "unused")
                self.assertEqual(FakeVerifier.seen["handshake_subject"], [subject])
                self.assertEqual(FakeVerifier.seen["attest_body"]["subject"], subject)

    def test_http_error_is_not_swallowed(self):
        FakeVerifier.handshake_status = 500
        with self.assertRaises(Exception) as ctx:
            client.attest(self.base, "s", "unused")
        self.assertIn("500", str(ctx.exception))
        self.assertNotIn("attest_body", FakeVerifier.seen)


class ConfirmationVectorTest(unittest.TestCase):
    """The same bytes are pinned in tests/vector.php for the PHP verifier."""

    def test_vector_1(self):
        self.assertEqual(client.confirmation(
            b"\x11" * 32, "00112233445566778899aabbccddeeff", "host.example.com",
            b"\x22" * 1184, b"\x33" * 1088).hex(),
            "a503bfca6f98b5237001f69dba4e03ca50366c519aecc81d606c89b2eff05353")

    def test_vector_2(self):
        self.assertEqual(client.confirmation(b"\x11" * 32, "s", "caff\u00e8", b"", b"").hex(),
                         "20b13d38c82d5fe4edd0035c13432c757e3de6a32c2d5056ebb8dbad0ba7a865")

    def test_every_field_is_bound(self):
        base = [b"\x11" * 32, "sid", "subject", b"pk", b"ct"]
        ref = client.confirmation(*base)
        for i in range(5):
            with self.subTest(field=i):
                args = list(base)
                args[i] = args[i] + (b"x" if isinstance(args[i], bytes) else "x")
                self.assertNotEqual(client.confirmation(*args), ref)


class EncapsulateInputTest(unittest.TestCase):
    """Refused before liboqs is called, so no library is needed."""

    def test_wrong_public_key_length_is_refused(self):
        for n in (0, client.PK_LEN - 1, client.PK_LEN + 1):
            with self.subTest(length=n):
                with self.assertRaises(ValueError):
                    client.encapsulate(None, b"\x00" * n)


@unittest.skipUnless(LIBOQS and os.path.isfile(LIBOQS),
                     "KEMPROOF_LIBOQS not set: no real ML-KEM-768 exchange run")
class RealExchangeTest(unittest.TestCase):
    """A genuine ML-KEM-768 exchange against liboqs."""

    @classmethod
    def setUpClass(cls):
        cls.lib = client.load(LIBOQS)
        u8p = ctypes.POINTER(ctypes.c_uint8)
        cls.lib.OQS_KEM_keypair.argtypes = [ctypes.c_void_p, u8p, u8p]
        cls.lib.OQS_KEM_keypair.restype = ctypes.c_int
        cls.lib.OQS_KEM_decaps.argtypes = [ctypes.c_void_p, u8p, u8p, u8p]
        cls.lib.OQS_KEM_decaps.restype = ctypes.c_int

    def _keypair(self):
        kem = self.lib.OQS_KEM_new(client.ALG)
        self.assertTrue(kem)
        try:
            pk = (ctypes.c_uint8 * client.PK_LEN)()
            sk = (ctypes.c_uint8 * 2400)()
            self.assertEqual(self.lib.OQS_KEM_keypair(kem, pk, sk), 0)
            return bytes(pk), sk
        finally:
            self.lib.OQS_KEM_free(kem)

    def test_ciphertext_decapsulates(self):
        pk, sk = self._keypair()
        ct, shared = client.encapsulate(self.lib, pk)
        self.assertEqual(len(ct), client.CT_LEN)
        kem = self.lib.OQS_KEM_new(client.ALG)
        try:
            ss = (ctypes.c_uint8 * client.SS_LEN)()
            ctbuf = (ctypes.c_uint8 * client.CT_LEN)(*ct)
            self.assertEqual(self.lib.OQS_KEM_decaps(kem, ss, ctbuf, sk), 0)
            self.assertNotEqual(bytes(ss), b"\x00" * client.SS_LEN)
            # Both sides reached the same secret: that is what the
            # confirmation will prove to the verifier.
            self.assertEqual(bytes(ss), shared)
        finally:
            self.lib.OQS_KEM_free(kem)

    def test_two_encapsulations_differ(self):
        pk, _ = self._keypair()
        self.assertNotEqual(client.encapsulate(self.lib, pk)[0],
                            client.encapsulate(self.lib, pk)[0])



def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(LIBOQS and os.path.isfile(LIBOQS) and shutil.which("php"),
                     "needs KEMPROOF_LIBOQS and php: no end-to-end run")
class EndToEndTest(unittest.TestCase):
    """The Python client against the PHP reference verifier, both real."""

    @classmethod
    def setUpClass(cls):
        cls.data = tempfile.mkdtemp(prefix="kemproof-")
        port = _free_port()
        env = dict(os.environ, KEMPROOF_LIBOQS=LIBOQS, KEMPROOF_DATA=cls.data)
        cls.proc = subprocess.Popen(
            ["php", "-d", "ffi.enable=true", "-S", "127.0.0.1:%d" % port, os.path.join(HERE, "..", "examples", "verifier.php")],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.base = "http://127.0.0.1:%d" % port
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            cls.proc.kill()
            raise RuntimeError("php -S did not start")
        cls.lib = client.load(LIBOQS)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)
        shutil.rmtree(cls.data, ignore_errors=True)

    def _post(self, payload):
        try:
            return 200, client.get_json(self.base + "/attest", payload)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def _handshake(self, subject):
        hs = client.get_json(self.base + "/handshake?subject=" + urllib.parse.quote(subject))
        pk = base64.b64decode(hs["public_key"])
        ct, ss = client.encapsulate(self.lib, pk)
        return hs, pk, ct, ss

    def _payload(self, subject, sid, ct, conf):
        return {"subject": subject, "session_id": sid,
                "ciphertext": base64.b64encode(ct).decode(),
                "confirmation": base64.b64encode(conf).decode()}

    def test_full_exchange_is_confirmed(self):
        record = client.attest(self.base, "e2e.example.com", LIBOQS)
        self.assertEqual(record["subject"], "e2e.example.com")
        self.assertEqual(record["protocol"], "kemproof/2")
        self.assertIs(record["confirmed"], True)

    def test_wrong_confirmation_is_refused_and_the_session_is_spent(self):
        hs, pk, ct, ss = self._handshake("s1.example.com")
        status, body = self._post(self._payload("s1.example.com", hs["session_id"], ct, b"\0" * 32))
        self.assertEqual(status, 403, body)
        self.assertIn("key confirmation failed", body["error"])
        # The right confirmation now comes too late: the session was single-use.
        good = client.confirmation(ss, hs["session_id"], "s1.example.com", pk, ct)
        status, _ = self._post(self._payload("s1.example.com", hs["session_id"], ct, good))
        self.assertEqual(status, 404)

    def test_random_ciphertext_is_refused(self):
        hs, pk, _, ss = self._handshake("s2.example.com")
        ct = os.urandom(client.CT_LEN)
        conf = client.confirmation(ss, hs["session_id"], "s2.example.com", pk, ct)
        status, body = self._post(self._payload("s2.example.com", hs["session_id"], ct, conf))
        self.assertEqual(status, 403, body)

    def test_replay_is_refused(self):
        hs, pk, ct, ss = self._handshake("s3.example.com")
        payload = self._payload("s3.example.com", hs["session_id"], ct,
                                client.confirmation(ss, hs["session_id"], "s3.example.com", pk, ct))
        self.assertEqual(self._post(payload)[0], 200)
        self.assertEqual(self._post(payload)[0], 404)

    def test_subject_must_match_handshake(self):
        hs, pk, ct, ss = self._handshake("s4.example.com")
        conf = client.confirmation(ss, hs["session_id"], "other.example.com", pk, ct)
        status, body = self._post(self._payload("other.example.com", hs["session_id"], ct, conf))
        self.assertEqual(status, 400, body)


if __name__ == "__main__":
    unittest.main()
