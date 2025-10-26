from secrets import compare_digest, randbits, token_bytes
from primefac import isprime

from pycrypt.hash import SHA256
from pycrypt.utils import xor_bytes


def generate_large_prime(bits: int = 1024, attempts: int = 10000) -> int:
    for _ in range(attempts):
        # randbits may produce values with MSB unset; force MSB and LSB (odd)
        candidate = randbits(bits) | (1 << (bits - 1)) | 1
        if isprime(candidate):
            return candidate
    raise TimeoutError(
        f"Failed to generate prime number of length {bits} in {attempts} attempts"
    )


def mgf1(seed: bytes, length: int, hash=SHA256) -> bytes:
    hlen = hash.DIGEST_SIZE

    if length > (hlen << 32):
        raise ValueError("Mask too long")

    T = b""
    counter = 0
    while len(T) < length:
        c = int.to_bytes(counter, 4, "big")
        T += hash(seed + c).digest()
        counter += 1

    return T[:length]


def oaep_encode(m: bytes, k: int, label: bytes = b"", hash=SHA256):
    hlen = hash.DIGEST_SIZE

    if k < 2 * hlen + 2:
        raise ValueError("Encoding Error: modulus too small for OAEP with this hash")

    mlen = len(m)
    max_mlen = k - (2 * hlen) - 2

    if mlen > max_mlen:
        raise ValueError(f"Encoding Error: message too long, can be at most {max_mlen}")

    lhash = hash(label).digest()
    ps = b"\x00" * (k - mlen - (2 * hlen) - 2)
    db = lhash + ps + b"\x01" + m

    seed = token_bytes(hlen)

    db_mask = mgf1(seed, k - hlen - 1, hash)
    masked_db = bytes(xor_bytes(db, db_mask))

    seed_mask = mgf1(masked_db, hlen, hash)
    masked_seed = bytes(xor_bytes(seed, seed_mask))

    return b"\x00" + masked_seed + masked_db


def oaep_decode(em: bytes, k: int, label: bytes = b"", hash=SHA256):
    hlen = hash.DIGEST_SIZE
    computed_lhash = hash(label).digest()

    if len(em) != k or k < (2 * hlen + 2):
        raise ValueError("Decoding Error: invalid padding length")

    if em[0] != 0:
        raise ValueError("Decoding Error: invalid padding sequence")

    masked_seed = em[1 : hlen + 1]
    masked_db = em[hlen + 1 :]

    seed_mask = mgf1(masked_db, hlen, hash)
    seed = bytes(xor_bytes(masked_seed, seed_mask))

    db_mask = mgf1(seed, k - hlen - 1, hash)
    db = bytes(xor_bytes(masked_db, db_mask))

    lhash = db[:hlen]

    if not compare_digest(lhash, computed_lhash):
        raise ValueError("Decoding error: label hash mismatch")

    rest = db[hlen:]

    try:
        idx = rest.index(b"\x01")
    except ValueError:
        raise ValueError("Decoding error: data block corruption")

    return rest[idx + 1 :]


def pss_encode(m: bytes, emlen: int, slen: int | None = None, hash=SHA256) -> bytes:
    hlen = hash.DIGEST_SIZE
    mhash = hash(m).digest()

    if slen is None:
        slen = hlen

    if emlen < hlen + slen + 2:
        raise ValueError("Encoding Error: message length mismatch")

    salt = token_bytes(slen)
    m_prime = b"\x00" * 8 + mhash + salt
    h = hash(m_prime).digest()

    ps = b"\x00" * (emlen - slen - hlen - 2)
    db = ps + b"\x01" + salt

    db_mask = mgf1(h, emlen - hlen - 1, hash)
    masked_db = bytes(xor_bytes(db, db_mask))

    return masked_db + h + b"\xbc"


def pss_verify(m: bytes, em: bytes, slen: int | None = None, hash=SHA256) -> bool:
    hlen = hash.DIGEST_SIZE
    emlen = len(em)
    mhash = hash(m).digest()

    if slen is None:
        slen = hlen

    if emlen < hlen + slen + 2:
        return False

    if em[-1] != 0xBC:
        return False

    masked_db = em[: emlen - hlen - 1]
    h = em[emlen - hlen - 1 : emlen - 1]

    db_mask = mgf1(h, emlen - hlen - 1, hash)
    db = bytes(xor_bytes(masked_db, db_mask))

    try:
        idx = db.index(b"\x01")
    except ValueError:
        return False

    salt = db[idx + 1 :]
    if len(salt) != slen:
        return False

    m_prime = b"\x00" * 8 + mhash + salt
    h_prime = hash(m_prime).digest()

    return compare_digest(h, h_prime)
