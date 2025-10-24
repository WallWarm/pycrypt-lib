from typing import Self

from egcd import egcd

from pycrypt.asymmetric.rsa.utils import generate_large_prime, oaep_decode, oaep_encode


class RSAKey:
    def __init__(self, n: int, e: int, d: int, p: int, q: int) -> None:
        self.n: int = n
        self.e: int = e
        self.d: int = d

        self.p: int = p
        self.q: int = q

        qInv, dP, dQ = self._precompute_crt(self.d, self.p, self.q)

        self.qInv: int = qInv
        self.dP: int = dP
        self.dQ: int = dQ

    def raw_encrypt(self, plaintext: int) -> int:
        return pow(plaintext, self.e, self.n)

    def raw_decrypt(self, ciphertext: int) -> int:
        if self.p and self.q and hasattr(self, "dP"):
            m1 = pow(ciphertext % self.p, self.dP, self.p)
            m2 = pow(ciphertext % self.q, self.dQ, self.q)

            h = (m1 - m2) * self.qInv % self.p
            m = m2 + h * self.q

            return m % self.n
        else:
            return pow(ciphertext, self.d, self.n)

    def oaep_encrypt(self, plaintext: bytes, label: bytes = b"") -> bytes:
        k = (self.n.bit_length() + 7) // 8

        em = oaep_encode(plaintext, k, label)

        m = int.from_bytes(em, "big")
        c = self.raw_encrypt(m)

        ciphertext = c.to_bytes(k, "big")

        return ciphertext

    def oaep_decrypt(self, ciphertext: bytes, label: bytes = b"") -> bytes:
        k = (self.n.bit_length() + 7) // 8

        if len(ciphertext) != k:
            raise ValueError("Decryption Error: ciphertext length mismatch")

        c = int.from_bytes(ciphertext, "big")
        m = self.raw_decrypt(c)

        em = m.to_bytes(k, "big")

        plaintext = oaep_decode(em, k, label)

        return plaintext

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
        qInv = qInv

        return qInv, dP, dQ
