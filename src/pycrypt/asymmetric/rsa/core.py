from secrets import randbits
from typing import Self

from egcd import egcd
from primefac import isprime


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

    def raw_encrypt(self, m: int) -> int:
        return pow(m, self.e, self.n)

    def raw_decrypt(self, c: int) -> int:
        if self.p and self.q and hasattr(self, "dP"):
            m1 = pow(c % self.p, self.dP, self.p)
            m2 = pow(c % self.q, self.dQ, self.q)

            h = (m1 - m2) * self.qInv % self.p
            m = m2 + h * self.q

            return m % self.n
        else:
            return pow(c, self.d, self.n)

    @classmethod
    def generate(cls, bits: int = 2048, e: int = 65537) -> Self:
        half = bits // 2

        while True:
            p = cls._generate_large_prime(half)
            q = cls._generate_large_prime(bits - half)

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

    @staticmethod
    def _generate_large_prime(bits: int = 1024, attempts: int = 10000) -> int:
        for _ in range(attempts):
            candidate = randbits(bits)
            if isprime(candidate):
                return candidate
        raise TimeoutError(
            f"Failed to generate prime number of length {bits} in {attempts} attempts."
        )
