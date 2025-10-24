import pytest
import secrets

from pycrypt.asymmetric import RSAKey  # adjust import path if needed
from pycrypt.hash import SHA256
from pycrypt.asymmetric.rsa.utils import generate_large_prime
from egcd import egcd


def random_message(max_len=64):
    return secrets.token_bytes(secrets.randbelow(max_len) + 1)


# --- Fundamental math layer tests ---
def test_i2osp_and_os2ip_roundtrip():
    for i in range(1, 100):
        n = secrets.randbits(64)
        b = RSAKey.i2osp(n, 8)
        assert RSAKey.os2ip(b) == n
        assert len(b) == 8


def test_generate_large_prime_produces_prime():
    p = generate_large_prime(256)
    assert isinstance(p, int)
    assert 250 < p.bit_length() < 260
    assert pow(2, p - 1, p) == 1


def test_key_generation_and_crt_consistency():
    key = RSAKey.generate()
    phi = (key.p - 1) * (key.q - 1)
    assert (key.e * key.d) % phi == 1

    assert key.dP == key.d % (key.p - 1)
    assert key.dQ == key.d % (key.q - 1)
    _, qInv, _ = egcd(key.q, key.p)
    qInv %= key.p
    assert key.qInv == qInv


def test_primitive_encrypt_decrypt_roundtrip():
    key = RSAKey.generate(512)
    m = secrets.randbelow(key.n - 1)
    c = key.primitive_encrypt(m)
    m2 = key.primitive_decrypt(c)
    assert m == m2, "primitive encrypt/decrypt mismatch"


def test_primitive_sign_verify_roundtrip():
    key = RSAKey.generate(512)
    m = secrets.randbelow(key.n - 1)
    sig = key.primitive_sign(m)
    verified = key.primitive_verify(sig)
    assert verified == m


# --- OAEP Tests ---
def test_oaep_roundtrip():
    key = RSAKey.generate(1024)
    message = b"hello OAEP!"
    ciphertext = key.oaep_encrypt(message)
    plaintext = key.oaep_decrypt(ciphertext)
    assert plaintext == message


def test_oaep_random_messages():
    key = RSAKey.generate(1024)
    for _ in range(5):
        m = random_message(64)
        ct = key.oaep_encrypt(m)
        pt = key.oaep_decrypt(ct)
        assert pt == m


def test_oaep_with_label():
    key = RSAKey.generate(1024)
    label = b"associated-data"
    m = b"label test"
    ct = key.oaep_encrypt(m, label)
    pt = key.oaep_decrypt(ct, label)
    assert pt == m


def test_oaep_invalid_ciphertext_tampered():
    key = RSAKey.generate(1024)
    m = b"tamper test"
    ct = bytearray(key.oaep_encrypt(m))
    # flip some bits
    ct[len(ct) // 2] ^= 0xFF
    with pytest.raises(ValueError):
        key.oaep_decrypt(bytes(ct))


def test_oaep_invalid_length():
    key = RSAKey.generate(1024)
    with pytest.raises(ValueError):
        key.oaep_decrypt(b"short")


# --- PSS Tests ---
def test_pss_roundtrip():
    key = RSAKey.generate(1024)
    msg = b"RSA-PSS signing test"
    sig = key.pss_sign(msg)
    ok = key.pss_verify(msg, sig)
    assert ok, "PSS signature verification failed"


def test_pss_random_messages():
    key = RSAKey.generate(1024)
    for _ in range(5):
        msg = random_message(64)
        sig = key.pss_sign(msg)
        assert key.pss_verify(msg, sig)


def test_pss_invalid_signature():
    key = RSAKey.generate(1024)
    msg = b"Message to sign"
    sig = bytearray(key.pss_sign(msg))
    sig[-1] ^= 0xFF  # corrupt last byte
    assert not key.pss_verify(msg, bytes(sig))


def test_pss_wrong_message():
    key = RSAKey.generate(1024)
    msg1 = b"message one"
    msg2 = b"message two"
    sig = key.pss_sign(msg1)
    assert not key.pss_verify(msg2, sig)


def test_pss_different_salt_lengths():
    key = RSAKey.generate(1024)
    msg = b"Salt len test"
    for slen in [8, 16, 32]:
        sig = key.pss_sign(msg, slen=slen)
        assert key.pss_verify(msg, sig, slen=slen)


# --- Property Tests ---
@pytest.mark.parametrize("bits", [1024, 2048])
def test_multiple_roundtrips(bits):
    key = RSAKey.generate(bits)
    hlen = SHA256.DIGEST_SIZE
    max_msg_len = key.k - 2 * hlen - 2  # OAEP max message length

    for _ in range(5):
        mlen = min(64, max_msg_len)  # ensure message fits OAEP
        m = random_message(mlen)

        # OAEP encrypt/decrypt
        ct = key.oaep_encrypt(m)
        pt = key.oaep_decrypt(ct)
        assert pt == m

        # PSS sign/verify
        sig = key.pss_sign(m)
        assert key.pss_verify(m, sig)


# --- Integration / Interop Sanity ---
def test_public_and_private_match():
    key = RSAKey.generate(1024)
    msg = b"Interop test"
    ct = key.oaep_encrypt(msg)
    pub_only = RSAKey(key.n, key.e, None, None, None)
    with pytest.raises(TypeError):
        pub_only.primitive_decrypt(1)


def test_encrypt_then_sign_then_verify():
    key = RSAKey.generate(1024)
    msg = b"Encrypt then sign test"
    ct = key.oaep_encrypt(msg)
    sig = key.pss_sign(ct)
    assert key.pss_verify(ct, sig)


# --- Edge Cases ---
def test_zero_message_encryption():
    key = RSAKey.generate()
    zero_bytes = b"\x00" * 8
    ct = key.oaep_encrypt(zero_bytes)
    pt = key.oaep_decrypt(ct)
    assert pt == zero_bytes


def test_max_message_size():
    key = RSAKey.generate(1024)
    hlen = SHA256().DIGEST_SIZE
    max_len = key.k - 2 * hlen - 2
    msg = b"A" * max_len
    ct = key.oaep_encrypt(msg)
    pt = key.oaep_decrypt(ct)
    assert pt == msg


def test_message_too_long_raises():
    key = RSAKey.generate(1024)
    hlen = SHA256().DIGEST_SIZE
    too_long = b"A" * (key.k - 2 * hlen - 1)
    with pytest.raises(ValueError):
        key.oaep_encrypt(too_long)


# --- Determinism / randomness checks ---
def test_oaep_randomness():
    key = RSAKey.generate(1024)
    msg = b"same"
    c1 = key.oaep_encrypt(msg)
    c2 = key.oaep_encrypt(msg)
    assert c1 != c2, "OAEP should be randomized"


def test_pss_randomness():
    key = RSAKey.generate(1024)
    msg = b"same"
    s1 = key.pss_sign(msg)
    s2 = key.pss_sign(msg)
    assert s1 != s2, "PSS should be randomized"
