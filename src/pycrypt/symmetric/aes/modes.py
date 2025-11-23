from abc import ABC, abstractmethod
from secrets import compare_digest
from typing import Final, Literal, override

from pycrypt.symmetric.aes.core import AESCore
from pycrypt.symmetric.aes.utils import (
    inc_counter,
    pad16,
    validate_len,
    validate_len_multiple,
)
from pycrypt.utils import PKCS7, xor_bytes


class _AESMode(ABC):
    """Abstract base class for AES block cipher modes.

    This class provides the foundation for implementing different AES modes
    (ECB, CBC, CTR, GCM). It handles low-level AES operations and provides
    utility functions for block handling, counter management, and XOR operations.

    Attributes:
        _aes (AESCore): The underlying AES block cipher instance.

    Example:
        >>> from pycrypt.symmetric.aes.modes import AES_ECB
        >>> key = b"0123456789abcdef"
        >>> aes = AES_ECB(key)
        >>> ciphertext = aes.encrypt(b"hello world")
        >>> aes.decrypt(ciphertext)
        b'hello world'
    """

    def __init__(self, key: bytes):
        """Initialize an AES mode with a secret key.

        Args:
            key (bytes): The AES key (16, 24, or 32 bytes for AES-128/192/256).
        """
        self._aes: AESCore = AESCore(key)

    # --- Encryption / Decryption ---

    @abstractmethod
    def encrypt(self, *args, **kwargs) -> bytes: ...  # pyright: ignore[reportUnknownParameterType, reportMissingParameterType]

    @abstractmethod
    def decrypt(self, *args, **kwargs) -> bytes: ...  # pyright: ignore[reportUnknownParameterType, reportMissingParameterType]

    # --- PRIVATE: Counter Logic for CTR/GCM ---

    def _ctr(self, data: bytes, initial_counter: bytes) -> bytes:
        validate_len("initial counter", initial_counter, 16)

        cipher = self._aes.cipher
        encrypted = bytearray()

        for idx, block in enumerate(self._chunk_blocks(data, fixed_length=False)):
            keystream = cipher(self._add_to_counter(initial_counter, idx))
            encrypted.extend(xor_bytes(block, keystream[: len(block)]))

        return bytes(encrypted)

    # --- PRIVATE: Helper Functions ---

    @staticmethod
    def _chunk_blocks(data: bytes, block_size: int = 16, fixed_length: bool = True):
        if fixed_length:
            validate_len_multiple("Data length", data, block_size)

        for i in range(0, len(data), block_size):
            yield data[i : i + block_size]

    @staticmethod
    def _add_to_counter(counter: bytes, num: int) -> bytes:
        counter_int = int.from_bytes(counter, "big") + num
        return counter_int.to_bytes(len(counter), "big")

    @override
    def __repr__(self):
        attrs: list[str] = []

        for name in ("iv", "nonce", "aad"):
            if hasattr(self, name):
                attrs.append(f"{name}={getattr(self, name)!r}")

        return f"{self.__class__.__name__}(key_len={len(self._aes._KEY)}, {', '.join(attrs)})"


class AES_ECB(_AESMode):
    """AES in ECB (Electronic Codebook) mode.

    ECB mode encrypts each 16-byte block independently. For messages that are
    not multiples of 16 bytes, padding (e.g., PKCS7) is required. This mode
    does not provide integrity/authentication, and identical plaintext blocks
    produce identical ciphertext blocks.

    Example:
        >>> key = b"0123456789abcdef"
        >>> aes = AES_ECB(key)
        >>> plaintext = b"Secret Message"
        >>> ct = aes.encrypt(plaintext)
        >>> aes.decrypt(ct)
        b'Secret Message'
    """

    def __init__(self, key: bytes):
        super().__init__(key)

    # --- Encryption / Decryption ---

    @override
    def encrypt(self, plaintext: bytes, *, pad: bool = True) -> bytes:
        """Encrypt plaintext using AES-ECB.

        Args:
            plaintext (bytes): The data to encrypt.
            pad (bool, optional): Whether to apply PKCS7 padding (default True).

        Returns:
            bytes: The ciphertext.
        """
        if pad:
            plaintext = PKCS7.pad(plaintext)
        else:
            validate_len_multiple("Plaintext length", plaintext)

        cipher = self._aes.cipher

        return b"".join(cipher(block) for block in self._chunk_blocks(plaintext))

    @override
    def decrypt(self, ciphertext: bytes, *, unpad: bool = True) -> bytes:
        """Decrypt ciphertext using AES-ECB.

        Args:
            ciphertext (bytes): The ciphertext to decrypt.
            unpad (bool, optional): Whether to remove PKCS7 padding (default True).

        Returns:
            bytes: The decrypted plaintext.
        """
        validate_len_multiple("Ciphertext length", ciphertext)

        inv = self._aes.inv_cipher
        out = b"".join(inv(block) for block in self._chunk_blocks(ciphertext))

        return PKCS7.unpad(out) if unpad else out


class AES_CBC(_AESMode):
    """AES in CBC (Cipher Block Chaining) mode.

    CBC mode XORs each plaintext block with the previous ciphertext block before
    encryption. Requires a 16-byte IV (initialization vector). Padding is required
    for non-multiple-of-block-length messages.

    Example:
        >>> key = b"0123456789abcdef"
        >>> iv = b"abcdef0123456789"
        >>> aes = AES_CBC(key)
        >>> ct = aes.encrypt(b"Secret Message", iv=iv)
        >>> aes.decrypt(ct, iv=iv)
        b'Secret Message'
    """

    def __init__(self, key: bytes):
        super().__init__(key)

    # --- Encryption / Decryption ---

    @override
    def encrypt(self, plaintext: bytes, *, iv: bytes, pad: bool = True) -> bytes:
        """Encrypt plaintext using AES-CBC.

        Args:
            plaintext (bytes): The data to encrypt.
            iv (bytes): 16-byte initialization vector.
            pad (bool, optional): Whether to apply PKCS7 padding (default True).

        Returns:
            bytes: The ciphertext.
        """
        if pad:
            plaintext = PKCS7.pad(plaintext)
        else:
            validate_len_multiple("Plaintext length", plaintext)
            validate_len("iv length", iv, 16)

        cipher = self._aes.cipher
        encrypted_blocks = bytearray()
        prev = iv

        for block in self._chunk_blocks(plaintext):
            x = xor_bytes(block, prev)
            ct = cipher(x)
            encrypted_blocks.extend(ct)
            prev = ct

        return bytes(encrypted_blocks)

    @override
    def decrypt(self, ciphertext: bytes, *, iv: bytes, unpad: bool = True) -> bytes:
        """Decrypt ciphertext using AES-CBC.

        Args:
            ciphertext (bytes): The ciphertext to decrypt.
            iv (bytes): 16-byte initialization vector used during encryption.
            unpad (bool, optional): Whether to remove PKCS7 padding (default True).

        Returns:
            bytes: The decrypted plaintext.
        """
        validate_len_multiple("Ciphertext length", ciphertext)
        validate_len("iv length", iv, 16)

        inv = self._aes.inv_cipher
        decrypted_blocks = bytearray()
        prev = iv

        for block in self._chunk_blocks(ciphertext):
            pt = xor_bytes(inv(block), prev)
            decrypted_blocks.extend(pt)
            prev = block

        plaintext = bytes(decrypted_blocks)

        if unpad:
            return PKCS7.unpad(plaintext)
        return plaintext


class AES_CTR(_AESMode):
    """AES in CTR (Counter) mode.

    CTR mode turns AES into a stream cipher. It combines a nonce with a counter
    to produce a keystream. Encryption and decryption are symmetric operations.
    Does not require padding. Requires an 8-byte nonce.

    Example:
        >>> key = b"0123456789abcdef"
        >>> nonce = b"12345678"
        >>> aes = AES_CTR(key)
        >>> ct = aes.encrypt(b"Secret Message", nonce=nonce)
        >>> aes.decrypt(ct, nonce=nonce)
        b'Secret Message'
    """

    def __init__(self, key: bytes):
        super().__init__(key)

    # --- Encryption / Decryption ---

    @override
    def encrypt(self, plaintext: bytes, *, nonce: bytes) -> bytes:
        """Encrypt plaintext using AES-CTR.

        Args:
            plaintext (bytes): Data to encrypt.
            nonce (bytes): 8-byte nonce for the counter block.

        Returns:
            bytes: Ciphertext.
        """
        return self._operate(plaintext, nonce)

    @override
    def decrypt(self, ciphertext: bytes, *, nonce: bytes) -> bytes:
        """Decrypt ciphertext using AES-CTR.

        Args:
            ciphertext (bytes): Data to decrypt.
            nonce (bytes): 8-byte nonce used during encryption.

        Returns:
            bytes: Decrypted plaintext.
        """
        return self._operate(ciphertext, nonce)

    # --- PRIVATE: Helper Function ---

    def _operate(self, data: bytes, nonce: bytes) -> bytes:
        validate_len("nonce", nonce, 8)

        counter = nonce + (b"\x00" * 8)

        return self._ctr(data, counter)


class AES_GCM(_AESMode):
    """AES in GCM (Galois/Counter Mode) with authentication.

    Provides both confidentiality and integrity. Requires a 12-byte nonce.
    Optional additional authenticated data (AAD) can be provided. Raises
    `AES_GCM.GCMAuthenticationError` if authentication fails.

    Example:
        >>> key = b"0123456789abcdef"
        >>> nonce = b"123456789012"
        >>> aes = AES_GCM(key)
        >>> ct, tag = aes.encrypt(b"Secret Message", nonce=nonce)
        >>> aes.decrypt(ct, nonce=nonce, tag=tag)
        b'Secret Message'
    """

    class GCMAuthenticationError(Exception):
        """Raised when GCM authentication fails."""

        pass

    _R: Final[int] = 0xE1000000000000000000000000000000
    _MASK128: Final[int] = (1 << 128) - 1
    _TAG_LENGTH: Final[int] = 16

    def __init__(self, key: bytes):
        super().__init__(key)
        self._H: Final[int] = int.from_bytes(self._aes.cipher(b"\x00" * 16), "big")

    # --- Encryption / Decryption ---

    @override
    def encrypt(  # pyright: ignore[reportIncompatibleMethodOverride]
        self, plaintext: bytes, *, nonce: bytes, aad: bytes = b""
    ) -> tuple[bytes, bytes]:
        """Encrypt and authenticate data using AES-GCM.

        Args:
            plaintext (bytes): Data to encrypt.
            nonce (bytes): 12-byte nonce.
            aad (bytes, optional): Additional authenticated data.

        Returns:
            tuple[bytes, bytes]: Ciphertext and 16-byte authentication tag.
        """
        return self._operate(plaintext, nonce, aad)

    @override
    def decrypt(
        self, ciphertext: bytes, *, nonce: bytes, tag: bytes, aad: bytes = b""
    ) -> bytes:
        """Decrypt and verify data using AES-GCM.

        Args:
            ciphertext (bytes): Ciphertext to decrypt.
            nonce (bytes): 12-byte nonce used during encryption.
            tag (bytes): 16-byte authentication tag from encryption.
            aad (bytes, optional): Additional authenticated data.

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            AES_GCM.GCMAuthenticationError: If authentication tag verification fails.
        """
        validate_len("tag", tag, self._TAG_LENGTH)

        plaintext, computed_tag = self._operate(ciphertext, nonce, aad, mode="decrypt")

        if not compare_digest(tag, computed_tag):
            raise AES_GCM.GCMAuthenticationError("GCM Authentication tag mismatch")

        return plaintext

    # --- PRIVATE: Helper Functions ---

    def _operate(
        self,
        data: bytes,
        nonce: bytes,
        aad: bytes = b"",
        mode: Literal["encrypt", "decrypt"] = "encrypt",
    ) -> tuple[bytes, bytes]:
        validate_len("nonce", nonce, 12)

        precounter = nonce + b"\x00\x00\x00\x01"
        operated = self._ctr(data, inc_counter(precounter, 32))

        if mode == "encrypt":
            cipher = operated
        else:
            cipher = data

        hashed_data = self._ghash(
            pad16(aad)
            + pad16(cipher)
            + len(aad).to_bytes(8, "big")
            + len(cipher).to_bytes(8, "big")
        )
        tag = self._ctr(hashed_data, precounter)[: self._TAG_LENGTH]
        return operated, tag

    def _ghash(self, data: bytes) -> bytes:
        validate_len_multiple("Data length", data)

        y = 0
        for block in self._chunk_blocks(data):
            b = int.from_bytes(block, "big")
            y = self._gf_mul(y ^ b, self._H)

        return y.to_bytes(16, "big")

    @staticmethod
    def _gf_mul(x: int, y: int) -> int:
        if x >> 128 or y >> 128:
            raise ValueError("Inputs must be 128-bit integers (0 <= value < 2**128)")

        z = 0
        v = x
        for i in range(128):
            if (y >> (127 - i)) & 1:
                z ^= v
            lsb = v & 1
            v >>= 1
            if lsb:
                v ^= AES_GCM._R

        return z & AES_GCM._MASK128
