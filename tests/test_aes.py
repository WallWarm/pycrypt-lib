import os

from pycrypt.symmetric import AES_CBC, AES_ECB, AES_CTR, AES_GCM
from pycrypt.symmetric.aes.core import AESCore

# Known AES test vector (AES-128, NIST/Rijndael single-block)
# Key:    000102030405060708090a0b0c0d0e0f
# Plain:  00112233445566778899aabbccddeeff
# Cipher: 69c4e0d86a7b0430d8cdb78070b4c55a
V_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
V_PT = bytes.fromhex("00112233445566778899aabbccddeeff")
V_CT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

def test_aescore_single_block():
    core = AESCore(V_KEY)
    ct = core.cipher(V_PT)
    assert ct == V_CT
    pt = core.inv_cipher(ct)
    assert pt == V_PT

def test_ecb_roundtrip_and_padding():
    key = V_KEY
    msg = b"Hello world!"
    e = AES_ECB(key)
    ct = e.encrypt(msg)
    assert len(ct) % 16 == 0
    pt = e.decrypt(ct)
    assert pt == msg

    block_msg = b"A" * 16
    ct2 = e.encrypt(block_msg)
    assert len(ct2) == 32
    assert e.decrypt(ct2) == block_msg


def test_cbc_roundtrip():
    key = V_KEY
    iv = os.urandom(16)
    msg = b"The quick brown fox jumps over the lazy dog"
    c = AES_CBC(key, iv)
    ct = c.encrypt(msg)
    assert len(ct) % 16 == 0
    pt = c.decrypt(ct)
    assert pt == msg


def test_ctr_roundtrip():
    key = V_KEY
    msg = b"The quick brown fox jumps over the lazy dog"
    nonce = os.urandom(8)
    c = AES_CTR(key)
    ct = c.encrypt(msg, nonce)
    assert len(ct) == len(msg)
    pt = c.decrypt(ct, nonce)
    assert pt == msg

def test_gcm_roundtrip():
    key = V_KEY
    msg = b"The quick brown fox jumps over the lazy dog"
    nonce = os.urandom(12)
    c = AES_GCM(key)
    ct, tag = c.encrypt(nonce, msg)
    assert len(ct) == len(msg)
    pt = c.decrypt(nonce, tag, ct)
    assert pt == msg
