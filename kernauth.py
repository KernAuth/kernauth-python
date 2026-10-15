import json
import urllib.error
import urllib.request


def check_body(app_id, license_key):
    return {
        "protocol_version": 1,
        "public_app_id": app_id,
        "client_version": "1.0.0",
        "license_key": license_key,
    }


def api_message(payload, fallback):
    error = payload.get("error") if isinstance(payload, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    return message if isinstance(message, str) and message else fallback


class KernAuth:
    def __init__(self, api, app_id):
        self.api = api
        self.app_id = app_id
        self.message = ""
        self.expires_at = None

    def check(self, license_key):
        request = urllib.request.Request(
            f"{self.api}/v1/client/check",
            data=json.dumps(check_body(self.app_id, license_key)).encode(),
            headers={"content-type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode())
                status = response.status
        except urllib.error.HTTPError as error:
            raw = error.read().decode()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = None
            self.message = api_message(payload, f"check failed ({error.code})")
            self.expires_at = None
            return False
        if status != 200 or not isinstance(payload, dict) or payload.get("valid") is not True:
            self.message = api_message(payload, f"check failed ({status})")
            self.expires_at = None
            return False
        expires = payload.get("expires_at")
        self.message = "License is active"
        self.expires_at = expires if isinstance(expires, str) else None
        return True
