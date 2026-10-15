# KernAuth Python example

Paste the public app ID from Developers into `main.py`. Python 3.

## Start

```python
app = KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__")
```

Type the license at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program checks that the key is valid and prints when it expires. It does not save a computer.

## Run

```
python test_kernauth.py
python main.py
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
