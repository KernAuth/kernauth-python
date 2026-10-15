import os
import sys

from kernauth import KernAuth


def license_key():
    from_env = os.environ.get("KERN_LICENSE_KEY", "").strip()
    if from_env:
        return from_env
    if sys.stdin.isatty():
        print("Enter license: ", end="", flush=True)
    return sys.stdin.readline().strip()


def main():
    app = KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__")
    if not app.check(license_key()):
        print(app.message)
        return 1
    print("Status: active")
    print(f"Expires: {app.expires_at}" if app.expires_at else "Expires: Lifetime")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
