from secrets import randbits
from typing import Self

from egcd import egcd
from primefac import isprime


class RSAKey:
    def __init__(
        self, n: int, e: int, d: int = None, p: int = None, q: int = None
    ) -> None:
        self.n, self.e, self.d, self.p, self.q = n, e, d, p, q
        if p and q:
            self._precompute_crt()

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

    def _precompute_crt(self):
        self.dP = self.d % (self.p - 1)
        self.dQ = self.d % (self.q - 1)
        _, qInv, _ = egcd(self.q, self.p)
        self.qInv = qInv

    def _generate_large_prime(bits=1024, attempts=10000):
        for _ in range(attempts):
            candidate = randbits(bits)
            if isprime(candidate):
                return candidate
        raise f"Failed to generate prime number of length {bits} in {attempts} attempts."
