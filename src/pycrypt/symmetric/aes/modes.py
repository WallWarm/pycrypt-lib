from abc import ABC, abstractmethod

from pycrypt.utils import _PKCS7, xor_bytes
from pycrypt.symmetric.aes.core import _AESCore


class _AESMode(ABC):
    def __init__(self, key: bytes):
        self._aes = _AESCore(key)

    @abstractmethod
    def encrypt(self, data: bytes, pad: bool = True) -> bytes: ...

    @abstractmethod
    def decrypt(self, data: bytes, unpad: bool = True) -> bytes: ...

    @staticmethod
    def chunk_blocks(data: bytes, block_size: int = 16):
        if len(data) % block_size != 0:
            raise ValueError("Data length must be multiple of block size")

        for i in range(0, len(data), block_size):
            yield data[i : i + block_size]

    def __repr__(self):
        return f"{self.__class__.__name__}(key_len={len(self._aes.KEY)}, iv={getattr(self, 'iv', None)})"


class AES_ECB(_AESMode):
    def __init__(self, key: bytes):
        super().__init__(key)

    def encrypt(self, data: bytes, pad: bool = True) -> bytes:
        if pad:
            data = _PKCS7.pad(data)
        elif len(data) % 16 != 0:
            raise ValueError("Plaintext length must be multiple of 16 when pad=False")

        encrypted = bytearray()
        for block in self.chunk_blocks(data):
            encrypted.extend(self._aes.cipher(block))

        return bytes(encrypted)

    def decrypt(self, data: bytes, unpad: bool = True) -> bytes:
        if len(data) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")

        out = bytearray()
        for block in self.chunk_blocks(data):
            out.extend(self._aes.inv_cipher(block))

        return _PKCS7.unpad(bytes(out), 16) if unpad else bytes(out)


class AES_CBC(_AESMode):
    def __init__(self, key: bytes, iv: bytes):
        super().__init__(key)
        self.iv = iv

    def encrypt(self, data: bytes, pad: bool = True) -> bytes:
        if pad:
            data = _PKCS7.pad(data)
        elif len(data) % 16 != 0:
            raise ValueError("Plaintext length must be multiple of 16 when pad=False")

        encrypted_blocks = []
        prev = self.iv
        for block in self.chunk_blocks(data):
            x = xor_bytes(block, prev)
            ct = self._aes.cipher(x)
            encrypted_blocks.append(ct)
            prev = ct

        return b"".join(encrypted_blocks)

    def decrypt(self, data: bytes, unpad: bool = True) -> bytes:
        if len(data) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")

        decrypted_blocks = []
        prev = self.iv
        for block in self.chunk_blocks(data):
            pt = xor_bytes(self._aes.inv_cipher(block), prev)
            decrypted_blocks.append(pt)
            prev = block

        plaintext = b"".join(decrypted_blocks)
        if unpad:
            return _PKCS7.unpad(plaintext)
        return plaintext
