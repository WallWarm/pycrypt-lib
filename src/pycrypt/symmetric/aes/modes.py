from abc import ABC, abstractmethod
from typing import override

from pycrypt.utils import PKCS7, xor_bytes
from pycrypt.symmetric.aes.core import AESCore


class _AESMode(ABC):
    def __init__(self, key: bytes):
        self._aes: AESCore = AESCore(key)

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes: ...

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes: ...

    @staticmethod
    def chunk_blocks(data: bytes, block_size: int = 16, fixed_length: bool = True):
        if fixed_length and len(data) % block_size != 0:
            raise ValueError("Data length must be multiple of block size")

        for i in range(0, len(data), block_size):
            yield data[i : i + block_size]
    
    @override
    def __repr__(self):
        return f"{self.__class__.__name__}(key_len={len(self._aes.KEY)}, iv={getattr(self, 'iv', None)})"


class AES_ECB(_AESMode):
    def __init__(self, key: bytes):
        super().__init__(key)
        
    @override
    def encrypt(self, data: bytes, pad: bool = True) -> bytes:
        if pad:
            data = PKCS7.pad(data)
        elif len(data) % 16 != 0:
            raise ValueError("Plaintext length must be multiple of 16 when pad=False")

        encrypted = bytearray()
        for block in self.chunk_blocks(data):
            encrypted.extend(self._aes.cipher(block))

        return bytes(encrypted)
        
    @override
    def decrypt(self, data: bytes, unpad: bool = True) -> bytes:
        if len(data) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")

        out = bytearray()
        for block in self.chunk_blocks(data):
            out.extend(self._aes.inv_cipher(block))

        return PKCS7.unpad(bytes(out), 16) if unpad else bytes(out)


class AES_CBC(_AESMode):
    def __init__(self, key: bytes, iv: bytes):
        super().__init__(key)
        self.iv: bytes = iv
        
    @override
    def encrypt(self, data: bytes, pad: bool = True) -> bytes:
        if pad:
            data = PKCS7.pad(data)
        elif len(data) % 16 != 0:
            raise ValueError("Plaintext length must be multiple of 16 when pad=False")

        encrypted_blocks: list[bytes] = []
        prev = self.iv
        for block in self.chunk_blocks(data):
            x = xor_bytes(block, prev)
            ct = self._aes.cipher(x)
            encrypted_blocks.append(ct)
            prev = ct

        return b"".join(encrypted_blocks)

    @override
    def decrypt(self, data: bytes, unpad: bool = True) -> bytes:
        if len(data) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")

        decrypted_blocks: list[bytearray] = []
        prev = self.iv
        for block in self.chunk_blocks(data):
            pt = xor_bytes(self._aes.inv_cipher(block), prev)
            decrypted_blocks.append(pt)
            prev = block

        plaintext = b"".join(decrypted_blocks)
        if unpad:
            return PKCS7.unpad(plaintext)
        return plaintext


class AES_CTR(_AESMode):
    def __init__(self, key: bytes, nonce: bytes):
        super().__init__(key)
        if len(nonce) != 8:
            raise ValueError("nonce must be 8 bytes long")
        self.nonce: bytes = nonce

    def _operate(self, data: bytes) -> bytes:
        counter = b"".join([self.nonce, bytes.fromhex("00 00 00 00 00 00 00 00")])
        blocks = self.chunk_blocks(data, fixed_length=False)
        encrypted = bytearray()
        for idx, block in enumerate(blocks):
            keystream = self._aes.cipher(self.add_to_counter(counter, idx))
            encrypted.extend(xor_bytes(block, keystream[: len(block)]))
        return bytes(encrypted)

    @override
    def encrypt(self, data: bytes) -> bytes:
        return self._operate(data)
    
    @override
    def decrypt(self, data: bytes) -> bytes:
        return self._operate(data)

    @staticmethod
    def add_to_counter(counter: bytes, num: int):
        return bytes.fromhex(f"{int.from_bytes(counter) + num:x}")
