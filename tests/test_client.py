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
import sys
import threading
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
            return b"\x02" * client.CT_LEN
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
        ct = client.encapsulate(self.lib, pk)
        self.assertEqual(len(ct), client.CT_LEN)
        kem = self.lib.OQS_KEM_new(client.ALG)
        try:
            ss = (ctypes.c_uint8 * client.SS_LEN)()
            ctbuf = (ctypes.c_uint8 * client.CT_LEN)(*ct)
            self.assertEqual(self.lib.OQS_KEM_decaps(kem, ss, ctbuf, sk), 0)
            self.assertNotEqual(bytes(ss), b"\x00" * client.SS_LEN)
        finally:
            self.lib.OQS_KEM_free(kem)

    def test_two_encapsulations_differ(self):
        pk, _ = self._keypair()
        self.assertNotEqual(client.encapsulate(self.lib, pk),
                            client.encapsulate(self.lib, pk))


if __name__ == "__main__":
    unittest.main()
