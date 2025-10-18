from abc import ABC, abstractmethod
from typing import Optional, override, ParamSpec, Generic, Final

from pycrypt.utils import PKCS7, xor_bytes, ceildiv
from pycrypt.symmetric.aes.core import AESCore


P = ParamSpec("P")


class _AESMode(ABC, Generic[P]):
    def __init__(self, key: bytes):
        self._aes: AESCore = AESCore(key)

    @abstractmethod
    def encrypt(self, plaintext: bytes, *args: P.args, **kwargs: P.kwargs) -> bytes: ...

    @abstractmethod
    def decrypt(
        self, ciphertext: bytes, *args: P.args, **kwargs: P.kwargs
    ) -> bytes: ...

    @staticmethod
    def chunk_blocks(data: bytes, block_size: int = 16, fixed_length: bool = True):
        if fixed_length and len(data) % block_size != 0:
            raise ValueError("Data length must be multiple of block size")

        for i in range(0, len(data), block_size):
            yield data[i : i + block_size]
    
    @staticmethod
    def validate_block_size(data: bytes, block_size: int = 16):
        if len(data) % block_size != 0:
            raise ValueError(f"Data length must be multiple of {block_size} bytes.")


    @override
    def __repr__(self):
        return f"{self.__class__.__name__}(key_len={len(self._aes.KEY)}, iv={getattr(self, 'iv', None)})"


class AES_ECB(_AESMode[bool]):
    def __init__(self, key: bytes):
        super().__init__(key)

    @override
    def encrypt(self, plaintext: bytes, pad: bool = True) -> bytes:
        if pad:
            plaintext = PKCS7.pad(plaintext)
        elif len(plaintext) % 16 != 0:
            raise ValueError("Plaintext length must be multiple of 16 when pad=False")

        encrypted = bytearray()
        for block in self.chunk_blocks(plaintext):
            encrypted.extend(self._aes.cipher(block))

        return bytes(encrypted)

    @override
    def decrypt(self, ciphertext: bytes, unpad: bool = True) -> bytes:
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")

        out = bytearray()
        for block in self.chunk_blocks(ciphertext):
            out.extend(self._aes.inv_cipher(block))

        return PKCS7.unpad(bytes(out), 16) if unpad else bytes(out)


class AES_CBC(_AESMode[bool]):
    def __init__(self, key: bytes, iv: bytes):
        super().__init__(key)
        self.iv: bytes = iv

    @override
    def encrypt(self, plaintext: bytes, pad: bool = True) -> bytes:
        if pad:
            plaintext = PKCS7.pad(plaintext)
        elif len(plaintext) % 16 != 0:
            raise ValueError("Plaintext length must be multiple of 16 when pad=False")

        encrypted_blocks: list[bytes] = []
        prev = self.iv
        for block in self.chunk_blocks(plaintext):
            x = xor_bytes(block, prev)
            ct = self._aes.cipher(x)
            encrypted_blocks.append(ct)
            prev = ct

        return b"".join(encrypted_blocks)

    @override
    def decrypt(self, ciphertext: bytes, unpad: bool = True) -> bytes:
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")

        decrypted_blocks: list[bytearray] = []
        prev = self.iv
        for block in self.chunk_blocks(ciphertext):
            pt = xor_bytes(self._aes.inv_cipher(block), prev)
            decrypted_blocks.append(pt)
            prev = block

        plaintext = b"".join(decrypted_blocks)
        if unpad:
            return PKCS7.unpad(plaintext)
        return plaintext


class AES_CTR(_AESMode[bytes]):
    def __init__(self, key: bytes):
        super().__init__(key)

    def _ctr(self, data: bytes, nonce: bytes) -> bytes:
        if len(nonce) != 8:
            raise ValueError("nonce must be 8 bytes long")
        counter = nonce + bytes.fromhex("00 00 00 00 00 00 00 00")
        blocks = self.chunk_blocks(data, fixed_length=False)
        encrypted = bytearray()
        for idx, block in enumerate(blocks):
            keystream = self._aes.cipher(self.add_to_counter(counter, idx))
            encrypted.extend(xor_bytes(block, keystream[: len(block)]))
        return bytes(encrypted)

    @override
    def encrypt(self, plaintext: bytes, nonce: bytes) -> bytes:
        return self._ctr(plaintext, nonce)

    @override
    def decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
        return self._ctr(ciphertext, nonce)

    @staticmethod
    def add_to_counter(counter: bytes, num: int):
        return bytes.fromhex(f"{int.from_bytes(counter) + num:x}")


class AES_GCM(_AESMode[[bytes, bytes]]):
    _R: Final[int] = 0xE1000000000000000000000000000000
    _MASK128: Final[int] = (1 << 128) - 1
    _TAGLENGTH: Final[int] = 16

    def __init__(self, key: bytes):
        super().__init__(key)
        self.H: Final[bytes] = self._aes.cipher(b"\x00" * 16)

    def _gctr(self, data: bytes, nonce: bytes) -> bytes:
        if len(nonce) != 16:
            raise ValueError("nonce must be 16 bytes long")
        blocks = self.chunk_blocks(data, fixed_length=False)
        encrypted = bytearray()
        for idx, block in enumerate(blocks):
            keystream = self._aes.cipher(self._add_to_counter(nonce, idx))
            encrypted.extend(xor_bytes(block, keystream[: len(block)]))
        return bytes(encrypted)

    @override
    def encrypt(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes = b"",
    ) -> tuple[bytes, bytes]:
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes long")

        precounter = nonce + b"\x00\x00\x00\x01"
        encrypted = self._gctr(plaintext, self._inc_s(precounter, 32))
        pad_cipher = 16 * ceildiv(len(encrypted), 16) - len(encrypted)
        pad_aad = 16 * ceildiv(len(aad), 16)
        hashed_data = self._ghash(
            aad
            + b"\x00" * pad_aad
            + encrypted
            + b"\x00" * pad_cipher
            + len(aad).to_bytes(8, "big")
            + len(encrypted).to_bytes(8, "big")
        )
        tag = self._gctr(hashed_data, precounter)[: self._TAGLENGTH]
        return (encrypted, tag)

    @override
    def decrypt(
        self, nonce: bytes, tag: bytes, ciphertext: bytes, aad: bytes = b""
    ) -> bytes:
        if len(tag) != self._TAGLENGTH:
            raise ValueError("tag must be 16 bytes long")
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes long")
        precounter = nonce + b"\x00\x00\x00\x01"
        decrypted = self._gctr(ciphertext, self._inc_s(precounter, 32))
        pad_cipher = 16 * ceildiv(len(ciphertext), 16) - len(ciphertext)
        pad_aad = 16 * ceildiv(len(aad), 16)
        hashed_data = self._ghash(
            aad
            + b"\x00" * pad_aad
            + ciphertext
            + b"\x00" * pad_cipher
            + len(aad).to_bytes(8, "big")
            + len(ciphertext).to_bytes(8, "big")
        )
        computed_tag = self._gctr(hashed_data, precounter)[: self._TAGLENGTH]
        if computed_tag != tag:
            raise AuthenticationError("GCM Authentication tag mismatch.")
        return decrypted

    @staticmethod
    def _gf_mul_int(x: int, y: int) -> int:
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

    @staticmethod
    def _gf_mul_bytes(x: bytes | bytearray, y: bytes | bytearray) -> bytes:
        if len(x) != 16 or len(y) != 16:
            raise ValueError("Both inputs must be exactly 16 bytes long")

        xi = int.from_bytes(x, "big")
        yi = int.from_bytes(y, "big")
        zi = AES_GCM._gf_mul_int(xi, yi)
        return zi.to_bytes(16, "big")

    @staticmethod
    def _add_to_counter(counter: bytes, num: int) -> bytes:
        return bytes.fromhex(f"{int.from_bytes(counter) + num:x}")

    def _ghash(self, data: bytes) -> bytes:
        if len(data) % 16 != 0:
            raise ValueError("Data length must be a multiple of 16 bytes")

        blocks = self.chunk_blocks(data)
        y0 = b"\x00" * 16
        for block in blocks:
            y0 = self._gf_mul_bytes(xor_bytes(y0, block), self.H)
        return y0

    @staticmethod
    def _inc_s(counter: bytes, s: int) -> bytes:
        if s % 8 != 0:
            raise ValueError("Increment must be a multiple of 8")
        if len(counter) * 8 < s:
            raise ValueError("len(counter) must be >= s bits")

        n_bytes = len(counter)
        s_bytes = s // 8

        msb = counter[: n_bytes - s_bytes]
        lsb = counter[-s_bytes:]

        lsb_val = int.from_bytes(lsb, "big")
        lsb_inc = (lsb_val + 1) % (1 << s)
        lsb_new = lsb_inc.to_bytes(s_bytes, "big")

        return msb + lsb_new


class AuthenticationError(Exception):
    pass
