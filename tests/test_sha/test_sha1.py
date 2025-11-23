import hashlib
import pytest
from pycrypt.hash import SHA1

# --- Known SHA1 test vectors ---
VECTORS = [
    (b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
    ),
    (
        b"The quick brown fox jumps over the lazy dog",
        "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
    ),
    (
        b"The quick brown fox jumps over the lazy cog",
        "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",
    ),
]


def reference_sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


# --- Basic vector tests ---
@pytest.mark.parametrize("data,expected", VECTORS)
def test_known_vectors(data, expected):
    s = SHA1(data)
    assert s.hexdigest() == expected
    assert s.digest() == hashlib.sha1(data).digest()


# --- Incremental update tests ---
@pytest.mark.parametrize(
    "chunk_sizes",
    [
        [1],
        [3, 7, 64, 13],
        [64],
        [128],
    ],
)
def test_incremental_updates(chunk_sizes):
    data = b"The quick brown fox jumps over the lazy dog" * 7
    s = SHA1()
    idx = 0
    i = 0
    while idx < len(data):
        size = chunk_sizes[i % len(chunk_sizes)]
        chunk = data[idx : idx + size]
        s.update(chunk)
        idx += size
        i += 1
    assert s.hexdigest() == reference_sha1(data)


# --- Test digest preserves state ---
def test_digest_state_preservation():
    s = SHA1(b"hello world")
    copy_hash = s._hash.copy()
    copy_buffer = s._buffer
    copy_len = s._message_byte_len
    d1 = s.digest()
    d2 = s.digest()
    assert d1 == d2
    assert s._hash == copy_hash
    assert s._buffer == copy_buffer
    assert s._message_byte_len == copy_len


# --- Test hexdigest consistency ---
def test_hexdigest_matches_digest_hex():
    s = SHA1(b"some data")
    assert s.hexdigest() == s.digest().hex()


# --- Reset behavior ---
def test_reset_functionality():
    s = SHA1(b"abc")
    first = s.hexdigest()
    s.reset()
    assert s._message_byte_len == 0
    assert s._buffer == b""
    s.update(b"abc")
    assert s.hexdigest() == first


# --- Multi-block message ---
def test_multi_block():
    data = b"A" * 1000
    s = SHA1()
    s.update(data)
    assert s.hexdigest() == reference_sha1(data)


# --- Update after digest continues correctly ---
def test_update_after_digest():
    s = SHA1()
    s.update(b"alpha")
    first_digest = s.hexdigest()
    s.update(b"beta")
    combined = reference_sha1(b"alpha" + b"beta")
    assert s.hexdigest() == combined
    assert first_digest != combined


# --- Schedule message sanity check ---
def test_schedule_message_known_block():
    block = b"\x00" * 64
    block = (1).to_bytes(4, "big") + block[4:]
    s = SHA1()
    W = s._schedule_message(block)
    assert W[0] == 1
    assert all(isinstance(x, int) for x in W)
    assert len(W) == 80
    expected_W16 = s._rotl(W[13] ^ W[8] ^ W[2] ^ W[0], 1)
    assert W[16] == expected_W16


# --- Optional long test ---
@pytest.mark.skip
def test_one_million_a():
    million = b"a" * 1_000_000
    s = SHA1()
    for _ in range(1000):
        s.update(b"a" * 1000)
    expected = "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
    assert s.hexdigest() == expected
