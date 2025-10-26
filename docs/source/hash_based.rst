Hash-Based Algorithms
=====================
Hash-based algorithms extend hash functions for cryptographic purposes:

- HMAC (Hash-based Message Authentication Code) provides message authentication and integrity using a shared key.

- HKDF (HMAC-based Key Derivation Function) derives secure cryptographic keys from a source key material. These are widely used in secure communications and key management.

.. autofunction:: pycrypt.hash.hmac

.. autofunction:: pycrypt.hash.hkdf