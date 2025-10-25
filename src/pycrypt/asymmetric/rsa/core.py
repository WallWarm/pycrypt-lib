from typing import Literal, Self

from egcd import egcd

from pycrypt.asymmetric.rsa.asn1 import (
    pem_to_priv_key,
    pem_to_pub_key,
    priv_key_to_pem,
    pub_key_to_pem,
)
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

        if all(param is not None for param in (d, p, q)):
            self.qInv, self.dP, self.dQ = self._precompute_crt(self.d, self.p, self.q)
        else:
            self.qInv = self.dP = self.dQ = None

        self.k: int = (self.n.bit_length() + 7) // 8

    @property
    def PUBLIC_KEY(self) -> tuple[int, int]:
        return self.n, self.e

    @property
    def PRIVATE_KEY(self) -> tuple[int, int, int | None, ...]:
        return self.n, self.e, self.d, self.p, self.q, self.dP, self.dQ, self.qInv

    def primitive_encrypt(self, message: int) -> int:
        return pow(message, self.e, self.n)

    def primitive_decrypt(self, ciphertext: int) -> int:
        if self.p and self.q:
            m1 = pow(ciphertext % self.p, self.dP, self.p)
            m2 = pow(ciphertext % self.q, self.dQ, self.q)

            h = (m1 - m2) * self.qInv % self.p
            m = m2 + h * self.q

            return m % self.n
        else:
            if self.d is None:
                raise TypeError(
                    "Private exponent missing: cannot decrypt/sign with public-only key"
                )
            return pow(ciphertext, self.d, self.n)

    def primitive_sign(self, message: int) -> int:
        return self.primitive_decrypt(message)

    def primitive_verify(self, signature: int) -> int:
        return self.primitive_encrypt(signature)

    def oaep_encrypt(
        self, message: bytes, label: bytes = b"", hash: type = SHA256
    ) -> bytes:
        em = oaep_encode(message, self.k, label, hash)

        m = self._os2ip(em)
        c = self.primitive_encrypt(m)

        ciphertext = self._i2osp(c, self.k)

        return ciphertext

    def oaep_decrypt(
        self, ciphertext: bytes, label: bytes = b"", hash: type = SHA256
    ) -> bytes:
        if len(ciphertext) != self.k:
            raise ValueError("Decryption Error: ciphertext length mismatch")

        c = self._os2ip(ciphertext)
        m = self.primitive_decrypt(c)

        em = self._i2osp(m, self.k)

        plaintext = oaep_decode(em, self.k, label, hash)

        return plaintext

    def pss_sign(
        self, message: bytes, slen: int | None = None, hash: type = SHA256
    ) -> bytes:
        em = pss_encode(message, self.k - 1, slen, hash)

        m = self._os2ip(em)
        s = self.primitive_sign(m)

        signature = self._i2osp(s, self.k)

        return signature

    def pss_verify(
        self,
        message: bytes,
        signature: bytes,
        slen: int | None = None,
        hash: type = SHA256,
    ) -> bool:
        if len(signature) != self.k:
            return False

        s = self._os2ip(signature)
        m = self.primitive_verify(s)

        em = self._i2osp(m, self.k)

        return pss_verify(message, em[1:], slen, hash)

    def export_key(self, type: Literal["public", "private"] = "public") -> str:
        if type not in ("public", "private"):
            raise ValueError("type must be either 'public' or 'private'")

        if type == "public":
            pem = pub_key_to_pem(*self.PUBLIC_KEY)
        elif type == "private":
            if self.d is None:
                raise TypeError(
                    "Private exponent missing: cannot export private key with public-only key"
                )
            pem = priv_key_to_pem(*self.PRIVATE_KEY)

        return pem

    @classmethod
    def import_key(cls, pem: str) -> Self:
        try:
            key = pem_to_pub_key(pem)
            return cls(key["n"], key["e"])
        except Exception:
            try:
                key = pem_to_priv_key(pem)
                return cls(key["n"], key["e"], key["d"], key["p"], key["q"])
            except Exception:
                raise ValueError(
                    "Could not parse PEM as a valid RSA public or private key"
                )

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
    def _os2ip(b: bytes) -> int:
        return int.from_bytes(b, "big")

    @staticmethod
    def _i2osp(x: int, x_len: int) -> bytes:
        return x.to_bytes(x_len, "big")
