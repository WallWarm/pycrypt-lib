from secrets import compare_digest
from abc import ABC, abstractmethod
from typing import Literal, Final, override

from pycrypt.utils import PKCS7, xor_bytes
from pycrypt.symmetric.aes.core import AESCore
from pycrypt.symmetric.aes.utils import (
    inc_counter,
    pad16,
    validate_len,
    validate_len_multiple,
)


class _AESMode(ABC):
    def __init__(self, key: bytes):
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
    def __init__(self, key: bytes):
        super().__init__(key)
        
    # --- Encryption / Decryption ---

    @override
    def encrypt(self, plaintext: bytes, *, pad: bool = True) -> bytes:
        if pad:
            plaintext = PKCS7.pad(plaintext)
        else:
            validate_len_multiple("Plaintext length", plaintext)

        cipher = self._aes.cipher

        return b"".join(cipher(block) for block in self._chunk_blocks(plaintext))

    @override
    def decrypt(self, ciphertext: bytes, *, unpad: bool = True) -> bytes:
        validate_len_multiple("Ciphertext length", ciphertext)

        inv = self._aes.inv_cipher
        out = b"".join(inv(block) for block in self._chunk_blocks(ciphertext))

        return PKCS7.unpad(out) if unpad else out


class AES_CBC(_AESMode):
    def __init__(self, key: bytes):
        super().__init__(key)
        
    # --- Encryption / Decryption ---

    @override
    def encrypt(self, plaintext: bytes, *, iv: bytes, pad: bool = True) -> bytes:
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
    def __init__(self, key: bytes):
        super().__init__(key)
        
    # --- Encryption / Decryption ---

    @override
    def encrypt(self, plaintext: bytes, *, nonce: bytes) -> bytes:
        return self._operate(plaintext, nonce)

    @override
    def decrypt(self, ciphertext: bytes, *, nonce: bytes) -> bytes:
        return self._operate(ciphertext, nonce)
        
    # --- PRIVATE: Helper Function ---

    def _operate(self, data: bytes, nonce: bytes) -> bytes:
        validate_len("nonce", nonce, 8)

        counter = nonce + (b"\x00" * 8)

        return self._ctr(data, counter)


class AES_GCM(_AESMode):
    class GCMAuthenticationError(Exception):
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
        return self._operate(plaintext, nonce, aad)

    @override
    def decrypt(
        self, ciphertext: bytes, *, nonce: bytes, tag: bytes, aad: bytes = b""
    ) -> bytes:
        validate_len("tag", tag, self._TAG_LENGTH)

        plaintext, computed_tag = self._operate(ciphertext, nonce, aad, mode="decrypt")

        if not compare_digest(tag, computed_tag):
            raise AES_GCM.GCMAuthenticationError("GCM Authentication tag mismatch.")

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
