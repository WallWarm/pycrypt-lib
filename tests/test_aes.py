import os
import pytest

from pycrypt.symmetric import AES_CBC, AES_ECB, AES_CTR, AES_GCM
from pycrypt.symmetric.aes.core import AESCore

# --- Known AES-128 test vector ---
V_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
V_PT = bytes.fromhex("00112233445566778899aabbccddeeff")
V_CT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

# --- AES-256 test vector ---
V_KEY_256 = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
)
V_PT_256 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
V_CT_256 = bytes.fromhex("f3eed1bdb5d2a03c064b5a7e3db181f8")


@pytest.mark.parametrize(
    "key,pt,ct", [(V_KEY, V_PT, V_CT), (V_KEY_256, V_PT_256, V_CT_256[:16])]
)
def test_aescore_known_vectors(key, pt, ct):
    core = AESCore(key)
    assert core.cipher(pt) == ct
    assert core.inv_cipher(ct) == pt


@pytest.mark.parametrize("message", [b"", b"A", b"16bytesstring!!", b"A" * 32])
def test_ecb_various_lengths(message):
    c = AES_ECB(V_KEY)
    ct = c.encrypt(message)
    assert len(ct) % 16 == 0
    pt = c.decrypt(ct)
    assert pt == message


def test_cbc_with_fixed_iv():
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    msg = b"Multiple blocks test message"
    c = AES_CBC(V_KEY)
    ct = c.encrypt(msg, iv=iv)
    pt = c.decrypt(ct, iv=iv)
    assert pt == msg


def test_cbc_random_iv_consistency():
    iv = os.urandom(16)
    msg = b"Random IV test message"
    c = AES_CBC(V_KEY)
    ct = c.encrypt(msg, iv=iv)
    pt = c.decrypt(ct, iv=iv)
    assert pt == msg


@pytest.mark.parametrize("length", [0, 1, 15, 16, 31, 32, 100])
def test_ctr_various_lengths(length):
    msg = os.urandom(length)
    nonce = os.urandom(8)
    c = AES_CTR(V_KEY)
    ct = c.encrypt(msg, nonce=nonce)
    pt = c.decrypt(ct, nonce=nonce)
    assert pt == msg
    assert len(ct) == len(msg)


@pytest.mark.parametrize("aad", [b"", b"header", b"Some long AAD data!"])
def test_gcm_aad_support(aad):
    msg = b"GCM test message with AAD"
    nonce = os.urandom(12)
    c = AES_GCM(V_KEY)
    ct, tag = c.encrypt(msg, nonce=nonce, aad=aad)
    pt = c.decrypt(ct, nonce=nonce, tag=tag, aad=aad)
    assert pt == msg


def test_gcm_tag_verification():
    msg = b"GCM integrity test"
    nonce = os.urandom(12)
    c = AES_GCM(V_KEY)
    ct, tag = c.encrypt(msg, nonce=nonce, aad=b"header")
    with pytest.raises(AES_GCM.GCMAuthenticationError):
        # Modify tag to simulate tampering
        c.decrypt(
            ct, nonce=nonce, tag=tag[:-1] + bytes([tag[-1] ^ 0xFF]), aad=b"header"
        )


def test_multiple_blocks_ecb_cbc():
    msg = b"1234567890ABCDEF" * 4  # 64 bytes
    # ECB
    ecb = AES_ECB(V_KEY)
    ct_ecb = ecb.encrypt(msg)
    pt_ecb = ecb.decrypt(ct_ecb)
    assert pt_ecb == msg

    # CBC
    iv = os.urandom(16)
    cbc = AES_CBC(V_KEY)
    ct_cbc = cbc.encrypt(msg, iv=iv)
    pt_cbc = cbc.decrypt(ct_cbc, iv=iv)
    assert pt_cbc == msg


@pytest.mark.skip
def test_aes_file_encryption():
    with open("tests/assets/frankenstein.txt", "rb") as f:
        data = f.read()
    key = os.urandom(16)
    iv = os.urandom(16)
    c = AES_CBC(key)
    ct = c.encrypt(data, iv=iv)

    with open("tests/assets/frankenstein.enc", "wb") as f:
        f.write(ct)

    pt = c.decrypt(ct, iv=iv)

    assert data == pt
