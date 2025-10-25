from pycrypt.hash.sha.variants import SHA256
from pycrypt.utils import xor_bytes


def hmac(key: bytes, message: bytes, hash=SHA256) -> bytes:
    B = hash.BLOCK_SIZE

    ipad = b"\x36" * B
    opad = b"\x5c" * B

    if len(key) > B:
        key = hash(key).digest()
    else:
        key = key + b"\x00" * (B - len(key))

    return hash(
        xor_bytes(key, opad) + hash(xor_bytes(key, ipad) + message).digest()
    ).digest()


def hkdf(ikm: bytes, length: int, salt: bytes = b"", info: bytes = b"", hash=SHA256):
    prk = _hkdf_extract(ikm, salt, hash)
    return _hkdf_expand(prk, info, length, hash)


def _hkdf_extract(ikm: bytes, salt: bytes = b"", hash=SHA256) -> bytes:
    hlen = hash.DIGEST_SIZE
    if not salt:
        salt = b"\x00" * hlen

    return hmac(salt, ikm)


def _hkdf_expand(prk: bytes, info: bytes, length: int, hash=SHA256):
    hlen = hash.DIGEST_SIZE
    if length > 255 * hlen:
        raise ValueError(f"length of output keying material should be <={255 * hlen}")

    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    return okm[:length]
