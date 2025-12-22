<h1 align="center">pycrypt</h1>

<p align="center">
  <em>A pure Python implementation of cryptographic primitives, written in a clean, Pythonic, and type-safe way.</em>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square&logo=python" alt="Python 3.9+" /></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="MIT License" /></a>
  <img src="https://img.shields.io/badge/status-release-green?style=flat-square" alt="Release" />
  <img href="https://github.com/aravindakshabalaji/pycrypt-lib" src="https://img.shields.io/github/actions/workflow/status/aravindakshabalaji/pycrypt-lib/.github/workflows/python-package.yml?label=tests&style=flat-square" alt="Build status" />
  <img src="https://img.shields.io/pypi/v/pycrypt-lib.svg" href="https://pypi.org/project/pycrypt-lib" alt="PyPI version"
</p>

> ⚠️ **Disclaimer:**
> `pycrypt` is an **educational cryptography library**.
> It is **not safe for production use**.
> Use only for **learning** how cryptographic algorithms work under the hood.

> **Do not roll your own crypto** in production code. Use a [safe, audited library](https://pypi.org/project/cryptography/) that has been vetted by professionals.

## Overview

`pycrypt` implements major cryptographic primitives **from scratch** in pure Python
with minimal dependencies. It is designed for learners and developers interested
in the inner workings of cryptography.

## Features

| Category       | Algorithm               | Description                                          |
| -------------- | ----------------------- | ---------------------------------------------------- |
| **Asymmetric** | **RSA**                 | OAEP encryption/decryption, PSS signing/verification |
|                | **Diffie–Hellman (DH)** | Modular exponentiation and HKDF-based key derivation |
| **Symmetric**  | **AES**                 | ECB, CBC, CTR, and GCM modes                         |
| **Hashing**    | **SHA-1**, **SHA-256**  | HMAC and HKDF included                               |

## Project Structure

```
pycrypt/
├── asymmetric/
│   ├── dh/
│   │   ├── core.py
│   │   ├── groups.py
│   │   └── keyformat.py
│   └── rsa/
│       ├── core.py
│       ├── keyformat.py
│       └── utils.py
├── hash/
│   ├── sha/
│   │   ├── core.py
│   │   ├── hmac.py
│   │   └── variants.py
├── symmetric/
│   └── aes/
│       ├── core.py
│       ├── modes.py
│       └── utils.py
├── utils/
│   ├── asn1.py
│   ├── padding.py
│   └── utils.py
└── main.py
```

## Installation

```bash
pip install pycrypt-lib
```

## Examples

### Diffie–Hellman (DH) Key Exchange

```python
from pycrypt.asymmetric import DH

params = DH.generate_parameters(2048)

alice_priv = params.generate_private_key()
bob_priv = params.generate_private_key()

alice_shared = alice_priv.exchange(bob_priv.public_key())
bob_shared = bob_priv.exchange(alice_priv.public_key())

assert alice_shared == bob_shared
print(f"Shared secret: {alice_shared.hex()}")
```

### RSA Encryption and Signing

```python
from pycrypt.asymmetric import RSAKey

key = RSAKey.generate(2048)
message = b"Hello RSA!"

cipher = key.oaep_encrypt(message)
plain = key.oaep_decrypt(cipher)

signature = key.pss_sign(message)
assert key.pss_verify(message, signature)
```

### AES (GCM Mode)

```python
from secrets import token_bytes
from pycrypt.symmetric import AES_GCM

key = token_bytes(16)
nonce = token_bytes(12)

aes = AES_GCM(key)
ciphertext, tag = aes.encrypt(b"Top Secret", nonce=nonce)
plaintext = aes.decrypt(ciphertext, nonce=nonce, tag=tag)

print(plaintext.decode())
```

### SHA-256 Hash

```python
from pycrypt.hash import SHA256

sha = SHA256()
sha.update(b"hello world")
print(sha.hexdigest())
```

## License

`pycrypt` is licensed under the **MIT License**.

See [LICENSE](LICENSE) for the full text.

> ⚠️ **Note:**
> This library is **not secure** for production use.
> It is a **learning and exploration tool** only.

## Links

- [Documentation](https://pycrypt-lib.readthedocs.io/en/latest/)
- [Github Repository](https://github.com/aravindakshabalaji/pycrypt-lib)
- [PyPI Package](https://pypi.org/project/pycrypt-lib/)

## Cryptography Reference Standards

- [FIPS PUB 197 – Advanced Encryption Standard (AES)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [FIPS PUB 180-4 – Secure Hash Standard (SHS)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [RFC 8017 – RSA Cryptography Standard (PKCS #1 v2.2)](https://www.rfc-editor.org/rfc/rfc8017)
- [RFC 2631 - Diffie-Hellman Key Agreement Method](https://www.rfc-editor.org/rfc/rfc2631)
