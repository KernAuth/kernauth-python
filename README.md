# KernAuth Python example

Protocol example. This is not the official SDK. The official client is the C++ SDK. This file calls the same activate, validate, and deactivate routes and checks the Ed25519 signature.

## Add it

```
python -m pip install cryptography==50.0.2
python -m unittest test_python.py
```

Paste the public app ID, key ID, and public key from Developers over the placeholders in `python.py`. Run with `KERN_LICENSE_KEY` and `KERN_INSTALLATION_ID` set. Persist one installation ID per device.

## Instance

```python
app = KernAuth(
    api="https://api.kernauth.com",
    app_id="__PUBLIC_APP_ID__",
    key_id="__KEY_ID__",
    public_key="__PUBLIC_KEY__",
)
```

## Activate

```python
if not app.activate(license_key, installation_id):
    raise SystemExit(app.message)
```

## Validate

```python
if not app.validate(license_key, installation_id):
    raise SystemExit(app.message)
```

## Deactivate

```python
if not app.deactivate(license_key, installation_id):
    raise SystemExit(app.message)
```

`app.message` is `Device deactivated` after a successful deactivate.

A patched program can still skip the check. These examples do not add anti-debug or anti-VM code.

Documentation: https://kernauth.apidog.io
