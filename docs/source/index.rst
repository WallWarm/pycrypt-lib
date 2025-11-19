.. pycrypt documentation master file, created by
   sphinx-quickstart on Sun Oct 26 15:18:10 2025.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

========================
pycrypt
========================

A pure Python implementation of cryptographic primitives, written in a clean,
Pythonic, and type-safe way.


.. note::
    **Disclaimer:** `pycrypt` is an **educational cryptography library**.
    It is **not safe for production use**. Use only to **learninge** how
    cryptographic algorithms work under the hood. For production, use a vetted library such as
    `cryptography <https://pypi.org/project/cryptography/>`_.

.. toctree::
    :maxdepth: 2
    :caption: API Reference

    asymmetric
    hash
    symmetric


Overview
========

`pycrypt` implements major cryptographic primitives **from scratch** in pure Python
with minimal dependencies. It is designed for learners and developers interested
in the inner workings of cryptography.

Features
========

.. list-table::
    :header-rows: 1
    :widths: 20 30 50

    * - Category
      - Algorithm
      - Description
    * - **Asymmetric**
      - **RSA**
      - OAEP encryption/decryption, PSS signing/verification
    * - **Asymmetric**
      - **Diffie–Hellman (DH)**
      - Modular exponentiation and HKDF-based key derivation
    * - **Symmetric**
      - **AES**
      - ECB, CBC, CTR, and GCM modes
    * - **Hashing**
      - **SHA-1**, **SHA-256**
      - HMAC and HKDF included


Installation
============

.. code-block:: bash

    pip install pycrypt-lib


Usage Examples
==============

Diffie–Hellman (DH) Key Exchange
--------------------------------

.. code-block:: python

    from pycrypt.asymmetric import DH

    params = DH.generate_parameters(2048)

    alice_priv = params.generate_private_key()
    bob_priv = params.generate_private_key()

    alice_shared = alice_priv.exchange(bob_priv.public_key())
    bob_shared = bob_priv.exchange(alice_priv.public_key())

    assert alice_shared == bob_shared
    print(f"Shared secret: {alice_shared.hex()}")


RSA Encryption and Signing
--------------------------

.. code-block:: python

    from pycrypt.asymmetric import RSAKey

    key = RSAKey.generate(2048)
    message = b"Hello RSA!"

    cipher = key.oaep_encrypt(message)
    plain = key.oaep_decrypt(cipher)

    signature = key.pss_sign(message)
    assert key.pss_verify(message, signature)


AES Encryption (GCM Mode)
-------------------------

.. code-block:: python

    from secrets import token_bytes
    from pycrypt.symmetric import AES_GCM

    key = token_bytes(16)
    nonce = token_bytes(12)

    aes = AES_GCM(key)
    ciphertext, tag = aes.encrypt(b"Top Secret", nonce=nonce)
    plaintext = aes.decrypt(ciphertext, nonce=nonce, tag=tag)

    print(plaintext.decode())


SHA-256 Hashing
---------------

.. code-block:: python

    from pycrypt.hash import SHA256

    sha = SHA256()
    sha.update(b"hello world")
    print(sha.hexdigest())

License
=======

**MIT License**

Copyright (c) 2025 Aravindaksha Balaji

.. code-block:: text

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

Links
=====

- `Documentation <https://pycrypt-lib.readthedocs.io/en/latest/>`_
- `Github Repository <https://github.com/aravindakshabalaji/pycrypt-lib>`_
- `PyPI Package <https://pypi.org/project/pycrypt-lib/>`_


Cryptography Reference Standards
================================

- `FIPS PUB 197 – Advanced Encryption Standard (AES) <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf>`_
- `FIPS PUB 180-4 – Secure Hash Standard (SHS) <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>`_
- `RFC 8017 – RSA Cryptography Standard (PKCS #1 v2.2) <https://www.rfc-editor.org/rfc/rfc8017>`_
- `RFC 2631 – Diffie-Hellman Key Agreement Method <https://www.rfc-editor.org/rfc/rfc2631>`_
