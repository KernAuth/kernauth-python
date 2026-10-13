import base64
import hashlib
import json
import os
import secrets
import urllib.request
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

API = "https://api.kernauth.com"
APP_ID = "__PUBLIC_APP_ID__"
KEY_ID = "__KEY_ID__"
PUBLIC_KEY = "__PUBLIC_KEY__"


class KernAuth:
    def __init__(self, api=API, app_id=APP_ID, key_id=KEY_ID, public_key=PUBLIC_KEY):
        self.api = api
        self.app_id = app_id
        self.key_id = key_id
        self.public_key = public_key
        self.success = False
        self.message = ""

    def activate(self, license_key, installation_id):
        return self._call("activate", license_key, installation_id, "License is active")

    def validate(self, license_key, installation_id):
        return self._call("validate", license_key, installation_id, "License is active")

    def deactivate(self, license_key, installation_id):
        return self._call("deactivate", license_key, installation_id, "Device deactivated")

    def _call(self, mode, license_key, installation_id, ok_message):
        try:
            request(mode, license_key, installation_id, self.api, self.app_id, self.key_id, self.public_key)
        except Exception as error:
            self.success = False
            self.message = str(error)
            return False
        self.success = True
        self.message = ok_message
        return True


if __name__ == "__main__":
    license_key = os.environ["KERN_LICENSE_KEY"]
    installation_id = os.environ["KERN_INSTALLATION_ID"]
    app = KernAuth(API, APP_ID, KEY_ID, PUBLIC_KEY)
    if not app.activate(license_key, installation_id) or not app.validate(license_key, installation_id) or not app.deactivate(license_key, installation_id):
        raise SystemExit(app.message)
    print(app.message)


FIELDS = ("protocol_version", "entitlement_id", "application_id", "license_id", "status",
          "features", "device_id", "issued_at", "expires_at", "server_time", "nonce", "key_id")


def canonical(entitlement):
    features = entitlement["features"]
    if isinstance(features, str):
        features = json.loads(features)
    values = dict(entitlement, features=json.dumps(features, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    lines = []
    for field in FIELDS:
        value = str(values[field])
        if "\n" in value or "\r" in value:
            raise ValueError("Invalid entitlement field")
        lines.append(f"{field}={value}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def verify_grant(response, nonce, app_id=APP_ID, key_id=KEY_ID, public_key=PUBLIC_KEY, now=None):
    ent = response["entitlement"]
    now = now or datetime.now(timezone.utc)
    expiry = datetime.fromisoformat(ent["expires_at"].replace("Z", "+00:00"))
    if (ent["protocol_version"] != 1 or ent["nonce"] != nonce or
            ent["application_id"] != app_id or ent["key_id"] != key_id or
            ent["status"] != "active" or expiry <= now):
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True))
        key.verify(base64.b64decode(response["signature"], validate=True), canonical(ent))
        return True
    except (InvalidSignature, ValueError):
        return False


def request(mode, license_key, installation_id, api=API, app_id=APP_ID, key_id=KEY_ID, public_key=PUBLIC_KEY):
    nonce = secrets.token_urlsafe(24)
    fingerprint = hashlib.sha256(f"kernauth-device-v1:{installation_id}".encode()).hexdigest()
    body = {"protocol_version": 1, "public_app_id": app_id, "client_version": "1.0.0",
            "license_key": license_key, "fingerprint_version": 1, "device_fingerprint": fingerprint,
            "installation_id": installation_id, "nonce": nonce}
    outgoing = urllib.request.Request(f"{api}/v1/client/{mode}",
                                     data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(outgoing, timeout=10) as result:
        response = json.load(result)
    if mode == "deactivate":
        if response.get("deactivated") is not True:
            raise RuntimeError("Deactivation was not confirmed")
    elif not verify_grant(response, nonce, app_id, key_id, public_key):
        raise RuntimeError("Invalid or expired signed entitlement")
