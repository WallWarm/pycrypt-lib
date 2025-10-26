Advanced Encryption Standard
============================

AES is a symmetric block cipher that encrypts and decrypts data using the same key. It supports multiple modes of operation:

- ECB – encrypts each block independently (no chaining).

- CBC – chains blocks to provide diffusion, requiring an IV.

- CTR – turns AES into a stream cipher using a counter.

- GCM – provides both encryption and authentication with a nonce.

AES is commonly used in secure messaging, file encryption, and TLS.


.. autoclass:: pycrypt.symmetric.AES_ECB

.. autoclass:: pycrypt.symmetric.AES_CBC

.. autoclass:: pycrypt.symmetric.AES_CTR

.. autoclass:: pycrypt.symmetric.AES_GCM
