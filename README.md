<h1 align="center">🔐 pycrypt</h1>

<p align="center">
  <em>A pure Python implementation of cryptographic primitives, written in a clean, Pythonic, and type-safe way.</em>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square&logo=python" alt="Python 3.9+" /></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="MIT License" /></a>
  <img src="https://img.shields.io/badge/status-release-green?style=flat-square" alt="Release" />
  <img href="https://github.com/WallWarm/pycrypt-lib" src="https://img.shields.io/github/actions/workflow/status/WallWarm/pycrypt-lib/.github/workflows/python-package.yml?label=tests&style=flat-square" alt="Build status" />
  <img src="https://img.shields.io/pypi/v/pycrypt-lib.svg" href="https://pypi.org/project/pycrypt-lib" alt="PyPI version"
</p>

> ⚠️ **Disclaimer:**
> `pycrypt` is an **educational cryptography library**.
> It is **not safe for production use**.
> Use only for **learning** how cryptographic algorithms work under the hood.

> **Do not roll your own crypto** in production code. Use a [safe, audited library](https://pypi.org/project/cryptography/) that has been vetted by professionals.

## 📜 Overview

`pycrypt` implements major cryptographic primitives **from scratch** in pure Python
with minimal dependencies. It is designed for learners and developers interested
in the inner workings of cryptography.

Analysing the code may help in:

- Learning how encryption, hashing, and key exchange algorithms work.
- Exploring low-level arithmetic operations.
- Teaching cryptography fundamentals to intermediate Python developers.



## 📦 Features

| Category       | Algorithm               | Description                                          |
| -------------- | ----------------------- | ---------------------------------------------------- |
| **Asymmetric** | **RSA**                 | OAEP encryption/decryption, PSS signing/verification |
|                | **Diffie–Hellman (DH)** | Modular exponentiation and HKDF-based key derivation |
| **Symmetric**  | **AES**                 | ECB, CBC, CTR, and GCM modes                         |
| **Hashing**    | **SHA-1**, **SHA-256**  | HMAC and HKDF included                               |

## 🗂️ Project Structure

```
pycrypt/
├── asymmetric/
│   ├── dh/
│   │   ├── core.py
│   │   └── groups.py
│   └── rsa/
│       ├── asn1.py
│       ├── core.py
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
│   ├── padding.py
│   └── utils.py
└── main.py
```

## 🚀 Installation

```bash
pip install pycrypt-lib
```

## 🧩 Examples

### 🔸 Diffie–Hellman (DH) Key Exchange

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

### 🔸 RSA Encryption and Signing

```python
from pycrypt.asymmetric import RSAKey

key = RSAKey.generate(2048)
message = b"Hello RSA!"

cipher = key.oaep_encrypt(message)
plain = key.oaep_decrypt(cipher)

signature = key.pss_sign(message)
assert key.pss_verify(message, signature)
```

### 🔸 AES (GCM Mode)

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

### 🔸 SHA-256 Hash

```python
from pycrypt.hash import SHA256

sha = SHA256()
sha.update(b"hello world")
print(sha.hexdigest())
```

## 🧠 Design Philosophy

- **Pure Python** - minimal external dependencies
- **Readable and modular** - each algorithm is split into core and implementation parts
- **Type-safe** - uses `typing` and `ruff` for static checks
- **Educational focus** - clarity > performance
- **Standards-aligned** - based on official cryptographic specs

Understanding how cryptography works is the first step toward using it safely.

## 🪪 License

**MIT License**

Copyright (c) 2025 Aravindaksha Balaji, Arnav Guntur

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

> ⚠️ **Note:**
> This library is **not secure** for production use.
> It is a **learning and exploration tool** only.

## 🔗 Links
- [Documentation](https://pycrypt-lib.readthedocs.io/en/latest/)
- [Github Repository](https://github.com/WallWarm/pycrypt-lib)
- [PyPI Package](https://pypi.org/project/pycrypt-lib/)

## 🌟 Cryptography Reference Standards

- [FIPS PUB 197 – Advanced Encryption Standard (AES)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [FIPS PUB 180-4 – Secure Hash Standard (SHS)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [RFC 8017 – RSA Cryptography Standard (PKCS #1 v2.2)](https://www.rfc-editor.org/rfc/rfc8017)
- [RFC 2631 - Diffie-Hellman Key Agreement Method](https://www.rfc-editor.org/rfc/rfc2631)
