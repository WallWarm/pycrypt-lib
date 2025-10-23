from typing import override

from pycrypt.hash.sha.core import SHA


class SHA256(SHA):
    block_size: int = 64
    digest_size: int = 32
    word_size: int = 32
    MASK: int = (1 << word_size) - 1

    @override
    @classmethod
    def _init_hash(cls) -> list[int]:
        return [
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A,
            0x510E527F,
            0x9B05688C,
            0x1F83D9AB,
            0x5BE0CD19,
        ]

    @override
    @classmethod
    def _get_constants(cls) -> list[int]:
        # fmt: off
        return [
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
            ]

    @override
    def _process_block(self, block: bytes):
        K = self._get_constants()
        W = self._schedule_message(block)
        a, b, c, d, e, f, g, h = self._hash

        for t in range(64):
            T1 = (h + self.Sigma_1(e) + self.ch(e, f, g) + K[t] + W[t]) & self.MASK
            T2 = (self.Sigma_0(a) + self.maj(a, b, c)) & self.MASK
            h, g, f, e, d, c, b, a = (
                g,
                f,
                e,
                (d + T1) & self.MASK,
                c,
                b,
                a,
                (T1 + T2) & self.MASK,
            )

        self._hash = [
            (x + y) & self.MASK for x, y in zip(self._hash, [a, b, c, d, e, f, g, h])
        ]

    @override
    def _schedule_message(self, block: bytes) -> list[int]:
        W = [0] * 64
        for i in range(64):
            if i < 16:
                W[i] = int.from_bytes(block[i * 4 : (i + 1) * 4], "big")
            else:
                W[i] = (
                    self.sigma_1(W[i - 2])
                    + W[i - 7]
                    + self.sigma_0(W[i - 15])
                    + W[i - 16]
                ) & self.MASK
        return W

    @classmethod
    def _rotr(cls, x: int, n: int, w: int = 32) -> int:
        n = n % w
        return (x >> n) | ((x << w - n) & cls.MASK)

    @classmethod
    def _shr(cls, x: int, n: int):
        return x >> n

    @classmethod
    def ch(cls, x: int, y: int, z: int):
        # Ch(x, y, z) = (x AND y) XOR ((NOT x) AND z)
        return ((x & y) ^ ((~x & cls.MASK) & z)) & cls.MASK

    @classmethod
    def maj(cls, x: int, y: int, z: int):
        # Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
        return ((x & y) ^ (x & z) ^ (y & z)) & cls.MASK

    @classmethod
    def Sigma_0(cls, x: int):
        return (cls._rotr(x, 2) ^ cls._rotr(x, 13) ^ cls._rotr(x, 22)) & cls.MASK

    @classmethod
    def Sigma_1(cls, x: int):
        return (cls._rotr(x, 6) ^ cls._rotr(x, 11) ^ cls._rotr(x, 25)) & cls.MASK

    @classmethod
    def sigma_0(cls, x: int):
        return (cls._rotr(x, 7) ^ cls._rotr(x, 18) ^ cls._shr(x, 3)) & cls.MASK

    @classmethod
    def sigma_1(cls, x: int):
        return (cls._rotr(x, 17) ^ cls._rotr(x, 19) ^ cls._shr(x, 10)) & cls.MASK
