import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from python import canonical, verify_grant


VECTORS = json.loads((Path(__file__).resolve().parent / "vectors.json").read_text())


class ProtocolVectors(unittest.TestCase):
    def test_worker_signatures(self):
        for vector in VECTORS["vectors"]:
            with self.subTest(vector=vector["name"]):
                fields = vector["fields"]
                grant = {"entitlement": fields, "signature": vector["signature"]}
                now = datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc)
                self.assertEqual(canonical(fields), vector["canonical"].encode())
                self.assertTrue(verify_grant(grant, fields["nonce"], fields["application_id"],
                                             fields["key_id"], vector["public_key"], now))
                self.assertFalse(verify_grant(grant, "wrong", fields["application_id"],
                                              fields["key_id"], vector["public_key"], now))
                self.assertFalse(verify_grant(grant, fields["nonce"], "pub_other_app",
                                              fields["key_id"], vector["public_key"], now))
                self.assertFalse(verify_grant(grant, fields["nonce"], fields["application_id"],
                                              "wrong-key", vector["public_key"], now))
                self.assertFalse(verify_grant(
                    {"entitlement": fields, "signature": vector["signature"] + "AA"},
                    fields["nonce"], fields["application_id"], fields["key_id"], vector["public_key"], now))
                self.assertFalse(verify_grant(grant, fields["nonce"], fields["application_id"],
                                              fields["key_id"], vector["public_key"],
                                              datetime(2026, 1, 1, 0, 16, tzinfo=timezone.utc)))
                tampered = {"entitlement": dict(fields, device_id="other"), "signature": vector["signature"]}
                self.assertFalse(verify_grant(tampered, fields["nonce"], fields["application_id"],
                                              fields["key_id"], vector["public_key"], now))


if __name__ == "__main__":
    unittest.main()
