import unittest

from kernauth import api_message, check_body


class CheckTests(unittest.TestCase):
    def test_body_and_message(self):
        self.assertEqual(check_body("pub_harbor_desktop", "KERN-ABCD-EFGH-IJKL-MNOP"), {
            "protocol_version": 1,
            "public_app_id": "pub_harbor_desktop",
            "client_version": "1.0.0",
            "license_key": "KERN-ABCD-EFGH-IJKL-MNOP",
        })
        self.assertEqual(api_message({"error": {"message": "Update required"}}, "no"), "Update required")
        self.assertEqual(api_message({}, "no"), "no")


if __name__ == "__main__":
    unittest.main()
