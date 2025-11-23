from pycrypt.hash.sha.variants import SHA256
from pycrypt.utils import xor_bytes


def hmac(key: bytes, message: bytes, hash=SHA256) -> bytes:
    """Compute HMAC (Hash-based Message Authentication Code) for a message.

    HMAC combines a secret key with a cryptographic hash function to produce
    a message authentication code, which can be used for integrity and authenticity checks.

    Example:
        >>> key = b"secret"
        >>> msg = b"hello world"
        >>> hmac(key, msg).hex()
        '...'  # 64-character hex for SHA-256

    Args:
        key (bytes): Secret key.
        message (bytes): Input message to authenticate.
        hash (class, optional): Hash function class (default is SHA256).

    Returns:
        bytes: The HMAC digest.
    """
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


def hkdf(
    ikm: bytes, length: int, salt: bytes = b"", info: bytes = b"", hash=SHA256
) -> bytes:
    """Derive cryptographic keys using HKDF (HMAC-based Key Derivation Function).

    HKDF extracts a pseudorandom key from input keying material and expands
    it to the desired output length using HMAC.

    Example:
        >>> ikm = b"input key material"
        >>> hkdf(ikm, 32).hex()
        '...'  # 64-character hex for 32-byte derived key

    Args:
        ikm (bytes): Input keying material.
        length (int): Desired length of output keying material in bytes.
        salt (bytes, optional): Optional salt value (default is empty).
        info (bytes, optional): Context/application-specific info (default is empty).
        hash (class, optional): Hash function class (default is SHA256).

    Returns:
        bytes: Derived key of specified length.
    """
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
