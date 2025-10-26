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
    """Represents an RSA key pair supporting encryption, decryption, signing, and verification.

    This class provides both low-level RSA primitives and high-level operations using
    OAEP (Optimal Asymmetric Encryption Padding) for encryption and PSS
    (Probabilistic Signature Scheme) for signing, along with key generation and PEM serialization.

    Example:
        >>> key = RSAKey.generate(2048)
        >>> ciphertext = key.oaep_encrypt(b"hello")
        >>> plaintext = key.oaep_decrypt(ciphertext)
        >>> assert plaintext == b"hello"

    Attributes:
        n (int): RSA modulus (product of two large primes, `p` and `q`).
        e (int): RSA public exponent.
        d (int | None): RSA private exponent (None for public-only keys).
        p (int | None): First prime factor of `n` (None for public-only keys).
        q (int | None): Second prime factor of `n` (None for public-only keys).
        dP (int | None): d mod (p−1), used for CRT optimization.
        dQ (int | None): d mod (q−1), used for CRT optimization.
        qInv (int | None): Multiplicative inverse of q mod p.
        k (int): Key length in bytes.
    """

    def __init__(
        self,
        n: int,
        e: int,
        d: int | None = None,
        p: int | None = None,
        q: int | None = None,
    ) -> None:
        """Initializes an RSAKey instance.

        Args:
            n (int): RSA modulus.
            e (int): RSA public exponent.
            d (int | None, optional): Private exponent. Defaults to None.
            p (int | None, optional): Prime factor p. Defaults to None.
            q (int | None, optional): Prime factor q. Defaults to None.

        Raises:
            ValueError: If invalid parameters are provided.
        """

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
        """tuple[int, int]: Returns the public key (n, e)."""
        return self.n, self.e

    @property
    def PRIVATE_KEY(self) -> tuple[int, int, int | None, ...]:
        """tuple[int, int, int | None, ...]: Returns the full private key components
        (n, e, d, p, q, dP, dQ, qInv).
        """
        return self.n, self.e, self.d, self.p, self.q, self.dP, self.dQ, self.qInv

    def primitive_encrypt(self, message: int) -> int:
        """Performs raw RSA encryption (modular exponentiation).

        Args:
            message (int): The message as an integer.

        Returns:
            int: The ciphertext integer.
        """
        return pow(message, self.e, self.n)

    def primitive_decrypt(self, ciphertext: int) -> int:
        """Performs raw RSA decryption, optionally using CRT optimization.

        Args:
            ciphertext (int): The ciphertext as an integer.

        Returns:
            int: The decrypted message as an integer.

        Raises:
            TypeError: If the private exponent is missing.
        """
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
        """Performs raw RSA signing (equivalent to decryption).

        Args:
            message (int): The message as an integer.

        Returns:
            int: The signature as an integer.
        """
        return self.primitive_decrypt(message)

    def primitive_verify(self, signature: int) -> int:
        """Performs raw RSA signature verification (equivalent to encryption).

        Args:
            signature (int): The signature as an integer.

        Returns:
            int: The verified message integer.
        """
        return self.primitive_encrypt(signature)

    def oaep_encrypt(
        self, message: bytes, label: bytes = b"", hash: type = SHA256
    ) -> bytes:
        """Encrypts a message using RSA with OAEP padding.

        Args:
            message (bytes): The plaintext message.
            label (bytes, optional): Optional label for OAEP encoding. Defaults to b"".
            hash (type, optional): Hash function class used in OAEP. Defaults to SHA256.

        Returns:
            bytes: The ciphertext.

        Raises:
            ValueError: If message length exceeds maximum allowed size.
        """
        em = oaep_encode(message, self.k, label, hash)

        m = self._os2ip(em)
        c = self.primitive_encrypt(m)

        ciphertext = self._i2osp(c, self.k)

        return ciphertext

    def oaep_decrypt(
        self, ciphertext: bytes, label: bytes = b"", hash: type = SHA256
    ) -> bytes:
        """Decrypts a message encrypted with RSA-OAEP.

        Args:
            ciphertext (bytes): The ciphertext to decrypt.
            label (bytes, optional): Label used during encryption. Defaults to b"".
            hash (type, optional): Hash function used during encryption. Defaults to SHA256.

        Returns:
            bytes: The decrypted plaintext.

        Raises:
            ValueError: If ciphertext length is invalid or decryption fails.
            TypeError: If private key is missing.
        """
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
        """Generates a digital signature using RSA-PSS.

        Args:
            message (bytes): The message to sign.
            slen (int | None, optional): Salt length. Defaults to hash length.
            hash (type, optional): Hash function used for PSS. Defaults to SHA256.

        Returns:
            bytes: The signature.
        """
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
        """Verifies a signature created with RSA-PSS.

        Args:
            message (bytes): The original message.
            signature (bytes): The RSA-PSS signature.
            slen (int | None, optional): Salt length. Defaults to hash length.
            hash (type, optional): Hash function used for PSS. Defaults to SHA256.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        if len(signature) != self.k:
            return False

        s = self._os2ip(signature)
        m = self.primitive_verify(s)

        em = self._i2osp(m, self.k)

        return pss_verify(message, em[1:], slen, hash)

    def export_key(self, type: Literal["public", "private"] = "public") -> str:
        """Exports the RSA key in PEM format.

        Args:
            type (Literal["public", "private"], optional): Key type to export.
                Must be either "public" or "private". Defaults to "public".

        Returns:
            str: The PEM-encoded RSA key.

        Raises:
            ValueError: If type is invalid.
            TypeError: If private key components are missing for private export.
        """
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
        """Imports an RSA key from a PEM-formatted string.

        Args:
            pem (str): The PEM-encoded RSA key.

        Returns:
            RSAKey: An RSAKey instance initialized with the imported key.

        Raises:
            ValueError: If the PEM cannot be parsed as a valid RSA key.
        """
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
        """Generates a new RSA key pair.

        Args:
            bits (int, optional): Key size in bits. Defaults to 2048.
            e (int, optional): Public exponent. Defaults to 65537.

        Returns:
            RSAKey: A new RSA key pair.
        """
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
