from secrets import compare_digest, randbits, token_bytes

from primefac import isprime

from pycrypt.hash import SHA256
from pycrypt.utils import xor_bytes


def generate_large_prime(bits: int = 1024, attempts: int = 10000) -> int:
    for _ in range(attempts):
        candidate = randbits(bits)
        if isprime(candidate):
            return candidate
    raise TimeoutError(
        f"Failed to generate prime number of length {bits} in {attempts} attempts."
    )


def mgf1(seed: bytes, length: int, hash_func=SHA256) -> bytes:
    hLen = hash_func.DIGEST_SIZE

    if length > (hLen << 32):
        raise ValueError("mask too long")

    T = b""

    counter = 0
    while len(T) < length:
        c = int.to_bytes(counter, 4, "big")
        T += hash_func(seed + c).digest()
        counter += 1

    return T[:length]


def oaep_encode(m: bytes, k: int, l: bytes = b"", hash=SHA256):
    hlen = hash.DIGEST_SIZE
    mlen = len(m)
    max_mlen = k - (2 * hlen) - 2

    if mlen > max_mlen:
        raise ValueError(f"Message too long: length can be at most {max_mlen}")

    lhash = hash(l).digest()
    ps = b"\x00" * (k - mlen - (2 * hlen) - 2)
    db = lhash + ps + b"\x01" + m

    seed = token_bytes(hlen)

    db_mask = mgf1(seed, k - hlen - 1)
    masked_db = bytes(xor_bytes(db, db_mask))

    seed_mask = mgf1(masked_db, hlen)
    masked_seed = bytes(xor_bytes(seed, seed_mask))

    return b"\x00" + masked_seed + masked_db


def oaep_decode(em: bytes, k: int, l: bytes = b"", hash=SHA256):
    hlen = hash.DIGEST_SIZE
    computed_lhash = hash(l).digest()

    if len(em) != k or k < (2 * hlen + 2):
        raise ValueError("Decryption Error: invalid padding length")

    if em[0] != 0:
        raise ValueError("Decryption Error: invalid padding sequence")

    masked_seed = em[1 : hlen + 1]
    masked_db = em[hlen + 1 :]

    seed_mask = mgf1(masked_db, hlen)
    seed = bytes(xor_bytes(masked_seed, seed_mask))

    db_mask = mgf1(seed, k - hlen - 1)
    db = bytes(xor_bytes(masked_db, db_mask))

    lhash = db[:hlen]

    if not compare_digest(lhash, computed_lhash):
        raise ValueError("Decryption error: label hash mismatch")

    rest = db[hlen:]

    try:
        idx = rest.index(b"\x01")
    except ValueError:
        raise ValueError("Decryption error: data block corruption")

    return rest[idx + 1 :]
