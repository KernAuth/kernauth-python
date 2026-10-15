# KernAuth Python example

Paste the public app ID, key ID, and public key from Developers into `python.py`. Install cryptography, then run the file.

## Instance

```python
app = KernAuth(
    api="https://api.kernauth.com",
    app_id="__PUBLIC_APP_ID__",
    key_id="__KEY_ID__",
    public_key="__PUBLIC_KEY__",
)
```

## Validate

```python
if not app.validate(license_key, installation_id):
    raise SystemExit(app.message)
print(f"Status: {app.entitlement['status']}")
print(f"Features: {app.entitlement['features']}")
print(f"License: {app.entitlement['license_id']}")
print(f"Check expires: {app.entitlement['expires_at']}")
```

A good check prints the status, the feature flags stored on the license, the license id, and when this check expires. Type the license key at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program reads the HWID from the computer. On Windows that is the signed-in user's SID. `KERN_INSTALLATION_ID` overrides that HWID.

## Run

```
python -m pip install cryptography==50.0.2
python -m unittest test_python.py
python python.py
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
