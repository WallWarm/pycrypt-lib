import hashlib
import pytest

from pycrypt.hash.sha.variants import SHA256


# --- Known SHA256 test vectors ---
VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
]


def reference_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- Basic digest tests using known vectors ---
@pytest.mark.parametrize("data,expected", VECTORS)
def test_known_vectors(data, expected):
    s = SHA256(data)
    assert s.hexdigest() == expected
    assert s.digest() == hashlib.sha256(data).digest()


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
def test_incremental_updates_equal_whole(chunk_sizes):
    data = b"The quick brown fox jumps over the lazy dog" * 7
    s = SHA256()
    i = 0
    idx = 0
    while idx < len(data):
        size = chunk_sizes[i % len(chunk_sizes)]
        chunk = data[idx : idx + size]
        s.update(chunk)
        idx += size
        i += 1

    assert s.hexdigest() == reference_sha256(data)


# --- Test update with empty bytes behaves as a no-op ---
def test_update_empty_bytes_noop():
    s = SHA256()
    s.update(b"")
    assert s._message_byte_len == 0
    assert s._buffer == b""
    s.update(b"abc")
    before_len = s._message_byte_len
    s.update(b"")
    assert s._message_byte_len == before_len


# --- Ensure digest() does not mutate state ---
def test_digest_idempotent_and_preserves_state():
    s = SHA256()
    s.update(b"hello world")
    copy_hash = s._hash.copy()
    copy_buffer = s._buffer
    copy_len = s._message_byte_len

    d1 = s.digest()
    d2 = s.digest()

    assert d1 == d2
    assert s._hash == copy_hash
    assert s._buffer == copy_buffer
    assert s._message_byte_len == copy_len


# --- Test hexdigest equals digest().hex() ---
def test_hexdigest_matches_digest_hex():
    s = SHA256(b"some data")
    assert s.hexdigest() == s.digest().hex()


# --- Reset behaviour ---
def test_reset_restores_initial_hash():
    s = SHA256(b"abc")
    assert s.hexdigest() == reference_sha256(b"abc")
    s.reset()
    s.update(b"abc")
    assert s.hexdigest() == reference_sha256(b"abc")
    assert s._message_byte_len == 3
    s.reset()
    assert s._message_byte_len == 0
    assert s._buffer == b""


# --- Test padding edge case where padding_len == 0 ---
def test_padding_boundary_case_length_55():
    msg = b"A" * 55
    s = SHA256()
    s.update(msg)
    padded = s._pad_message()
    assert len(padded) % s.BLOCK_SIZE == 0
    bit_len = (len(msg) * 8).to_bytes(8, "big")
    assert padded[-8:] == bit_len
    assert padded[len(msg)] == 0x80


# --- parse_message yields exact BLOCK_SIZE chunks and schedule words match bytes ---
def test_parse_message_and_schedule_message_first_16_words():
    msg = b"".join(bytes([i % 256]) for i in range(128))
    s = SHA256()
    s.update(msg)
    padded = s._pad_message()
    blocks = list(SHA256._parse_message(padded))
    assert all(len(b) == s.BLOCK_SIZE for b in blocks)
    W = s._schedule_message(blocks[0])
    assert isinstance(W, list)
    assert len(W) == 64
    for i in range(16):
        expected = int.from_bytes(blocks[0][i * 4 : (i + 1) * 4], "big")
        assert W[i] == expected


# --- Constants shape and length ---
def test_constants_length_and_type():
    K = SHA256._get_constants()
    assert isinstance(K, list)
    assert len(K) == 64
    assert all(isinstance(x, int) for x in K)


# --- Multi-block hash correctness ---
def test_multi_block_messages_match_hashlib():
    data = b"A" * 1000
    s = SHA256()
    s.update(data)
    assert s.hexdigest() == reference_sha256(data)


# --- Test hashing after calling digest: ---
def test_update_after_digest_continues_correctly():
    s = SHA256()
    s.update(b"alpha")
    first_digest = s.hexdigest()
    s.update(b"beta")
    combined = hashlib.sha256(b"alpha" + b"beta").hexdigest()
    assert s.hexdigest() == combined
    assert first_digest != combined


# --- Ensure schedule produces expected values for a simple deterministic block ---
def test_schedule_message_known_block():
    block = b"\x00" * 64
    block = (1).to_bytes(4, "big") + block[4:]
    s = SHA256()
    W = s._schedule_message(block)
    assert W[0] == 1
    assert all(isinstance(x, int) for x in W)
    assert len(W) == 64


# --- Optional long test ---
@pytest.mark.skip
def test_one_million_a():
    # Known SHA256 of 1,000,000 'a' characters:
    # cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0
    million = b"a" * 1_000_000
    s = SHA256()
    for _ in range(1000):
        s.update(b"a" * 1000)
    assert (
        s.hexdigest()
        == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    )
