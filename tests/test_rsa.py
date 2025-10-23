import os
import pytest

from pycrypt.asymmetric import RSAKey


def test_rsa_raw():
    m = int.from_bytes(os.urandom(32), "big")
    k = RSAKey.generate()
    assert m == k.raw_decrypt(k.raw_encrypt(m))
