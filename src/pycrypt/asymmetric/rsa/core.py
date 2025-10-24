from typing import Self

from egcd import egcd

from pycrypt.asymmetric.rsa.utils import (
    generate_large_prime,
    oaep_decode,
    oaep_encode,
    pss_encode,
    pss_verify,
)
from pycrypt.hash import SHA256


class RSAKey:
    def __init__(
        self,
        n: int,
        e: int,
        d: int | None = None,
        p: int | None = None,
        q: int | None = None,
    ) -> None:
        self.n: int = n
        self.e: int = e
        self.d: int | None = d

        self.p: int | None = p
        self.q: int | None = q

        if self.d is not None and self.p is not None and self.q is not None:
            qInv, dP, dQ = self._precompute_crt(self.d, self.p, self.q)
            self.qInv: int = qInv
            self.dP: int = dP
            self.dQ: int = dQ

        self.k = (self.n.bit_length() + 7) // 8

    def primitive_encrypt(self, message: int) -> int:
        return pow(message, self.e, self.n)

    def primitive_decrypt(self, ciphertext: int) -> int:
        if self.p and self.q and self.dP is not None:
            m1 = pow(ciphertext % self.p, self.dP, self.p)
            m2 = pow(ciphertext % self.q, self.dQ, self.q)

            h = (m1 - m2) * self.qInv % self.p
            m = m2 + h * self.q

            return m % self.n
        else:
            if self.d is None:
                raise TypeError(
                    "Private exponent missing: cannot decrypt with public-only key"
                )
            return pow(ciphertext, self.d, self.n)

    def primitive_sign(self, message: int) -> int:
        return self.primitive_decrypt(message)

    def primitive_verify(self, signature: int) -> int:
        return self.primitive_encrypt(signature)

    def oaep_encrypt(self, message: bytes, label: bytes = b"", hash=SHA256) -> bytes:
        em = oaep_encode(message, self.k, label, hash)

        m = self.os2ip(em)
        c = self.primitive_encrypt(m)

        ciphertext = self.i2osp(c, self.k)

        return ciphertext

    def oaep_decrypt(self, ciphertext: bytes, label: bytes = b"", hash=SHA256) -> bytes:
        if len(ciphertext) != self.k:
            raise ValueError("Decryption Error: ciphertext length mismatch")

        c = self.os2ip(ciphertext)
        m = self.primitive_decrypt(c)

        em = self.i2osp(m, self.k)

        plaintext = oaep_decode(em, self.k, label, hash)

        return plaintext

    def pss_sign(self, message: bytes, slen: int | None = None, hash=SHA256) -> bytes:
        em = pss_encode(message, self.k - 1, slen, hash)

        m = self.os2ip(em)
        s = self.primitive_sign(m)

        signature = self.i2osp(s, self.k)

        return signature

    def pss_verify(
        self, message: bytes, signature: bytes, slen: int | None = None, hash=SHA256
    ) -> bool:
        if len(signature) != self.k:
            return False

        s = self.os2ip(signature)
        m = self.primitive_verify(s)

        em = self.i2osp(m, self.k)

        return pss_verify(message, em[1:], slen, hash)

    @classmethod
    def generate(cls, bits: int = 2048, e: int = 65537) -> Self:
        half = bits // 2

        while True:
            p = generate_large_prime(half)
            q = generate_large_prime(bits - half)

            if p == q:
                continue

            n = p * q
            phi = (p - 1) * (q - 1)

            gcd, d, _ = egcd(e, phi)
            assert abs(gcd) == 1

            if d < 0:
                d += phi

            return cls(n, e, d, p, q)

    @staticmethod
    def _precompute_crt(d: int, p: int, q: int) -> tuple[int, int, int]:
        dP = d % (p - 1)
        dQ = d % (q - 1)
        _, qInv, _ = egcd(q, p)
        qInv %= p

        return qInv, dP, dQ

    @staticmethod
    def os2ip(b: bytes) -> int:
        return int.from_bytes(b, "big")

    @staticmethod
    def i2osp(x: int, x_len: int) -> bytes:
        return x.to_bytes(x_len, "big")
