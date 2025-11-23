from dataclasses import dataclass
from secrets import randbelow
from typing import Literal, Self

from pycrypt.asymmetric.dh.groups import GROUPS
from pycrypt.asymmetric.dh.keyformat import (
    pem_to_priv_key,
    pem_to_pub_key,
    priv_key_to_pem,
    pub_key_to_pem,
)
from pycrypt.hash import hkdf


def int_to_bytes(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


@dataclass(slots=True, frozen=True)
class DHParameters:
    """Represents Diffie–Hellman (DH) group parameters.

    This class is aliased under the name :mod:`DH` for easier access.

    This class defines the mathematical parameters used for the
    Diffie–Hellman key exchange: the large prime modulus `p`, the generator `g`,
    and optionally the subgroup order `q`. These parameters define the
    finite cyclic group in which all DH operations occur.

    Example:
        >>> params = DHParameters.generate_parameters(key_size=2048)
        >>> priv = params.generate_private_key()
        >>> pub = priv.public_key()
    """

    p: int  #: The large prime modulus.
    g: int  #: The generator of the subgroup.
    q: int | None = None  #: Optional subgroup order, if known.

    @classmethod
    def generate_parameters(
        cls, key_size: Literal[2048, 3072, 4096, 6144, 8192] = 2048
    ):
        """Generate standardized Diffie–Hellman parameters.

        Uses predefined MODP groups from :mod:`pycrypt.asymmetric.dh.groups`.

        Args:
            key_size (Literal[2048, 3072, 4096, 6144, 8192], optional):
                The bit size of the DH group to use. Defaults to 2048.

        Returns:
            DHParameters: The generated DH parameter set.

        Raises:
            ValueError: If `key_size` is not one of the supported group sizes.
        """
        if key_size not in GROUPS:
            raise ValueError("key_size must be only: 2048, 3072, 4096, 6144, or 8192")

        return cls(*GROUPS[key_size])

    def generate_private_key(self, bits: int | None = None) -> "DHPrivateKey":
        """Generate a private key for this parameter set.

        Args:
            bits (int | None, optional): Bit length of the private key.
                If ``None``, a secure default based on the parameter size is used.

        Returns:
            DHPrivateKey: The generated private key instance.
        """
        p, q = self.p, self.q

        if q:
            x = 2 + randbelow(q - 3)
        else:
            if bits is None:
                bits = max(256, p.bit_length() - 1)

            while True:
                x = 2 + randbelow(p - 3)
                if 2 <= x <= p - 2:
                    break

        return DHPrivateKey(x, self)


@dataclass(slots=True, frozen=True)
class DHPublicKey:
    """Represents a Diffie–Hellman public key."""

    y: int  #: The computed public key value.
    params: DHParameters  #: The DH parameter set used to generate this key.

    def to_bytes(self) -> bytes:
        """Serialize the public key to bytes.

        Returns:
            bytes: The big-endian representation of the public key value.
        """
        return int_to_bytes(self.y)

    @classmethod
    def from_bytes(cls, b: bytes, params: DHParameters) -> Self:
        """Deserialize a public key from bytes.

        Args:
            b (bytes): The byte sequence representing the public key.
            params (DHParameters): The DH parameter set associated with this key.

        Returns:
            DHPublicKey: The reconstructed public key object.
        """
        return cls(bytes_to_int(b), params)

    def export_key(self) -> str:
        """Exports the DH public key in PEM format.

        Returns:
            str: The PEM-encoded DH public key.
        """
        return pub_key_to_pem(self.params.p, self.params.g, self.y)

    @classmethod
    def import_key(cls, pem: str) -> Self:
        """Imports a DH public key from a PEM-formatted string.

        Args:
            pem (str): The PEM-encoded DH public key.

        Returns:
            DHPublicKey: A DHPublicKey instance initialized with the imported key.

        Raises:
            ValueError: If the PEM cannot be parsed as a valid DH public key.
        """
        try:
            key = pem_to_pub_key(pem)
            return cls(key["y"], DHParameters(key["p"], key["g"]))
        except Exception:
            raise ValueError("Could not parse PEM as public key")


class DHPrivateKey:
    """Represents a Diffie–Hellman private key and key exchange operations."""

    def __init__(self, x: int, params: DHParameters) -> None:
        """Initialize a private key instance.

        Args:
            x (int): The private scalar value.
            params (DHParameters): The DH parameter set used.
        """
        self.x: int = x
        self.params: DHParameters = params

    def public_key(self) -> DHPublicKey:
        """Compute the public key corresponding to this private key.

        Returns:
            DHPublicKey: The derived public key.
        """
        return DHPublicKey(pow(self.params.g, self.x, self.params.p), self.params)

    def exchange(
        self,
        peer_public: DHPublicKey,
        *,
        info: bytes = b"",
        length: int = 32,
        salt: bytes | None = None,
    ) -> bytes:
        """Perform a key exchange with a peer and derive a shared secret.

        Uses HKDF as a key derivation function on the raw shared secret.

        Args:
            peer_public (DHPublicKey): The peer's public key.
            info (bytes, optional): Context/application-specific data for HKDF.
            length (int, optional): Desired length of the derived key in bytes.
            salt (bytes | None, optional): Optional salt for HKDF.

        Returns:
            bytes: The derived shared secret.
        """
        z = self._compute_raw_shared(peer_public)
        return hkdf(int_to_bytes(z), length, salt or b"", info)

    def zeroize(self) -> None:
        """Attempt to securely erase the private scalar from memory."""
        try:
            self.x = 0
        except Exception:
            pass

    def export_key(self) -> str:
        """Exports the DH private key in PEM format.

        Returns:
            str: The PEM-encoded DH private key.
        """
        return priv_key_to_pem(self.params.p, self.params.g, self.x)

    @classmethod
    def import_key(cls, pem: str) -> Self:
        """Imports a DH private key from a PEM-formatted string.

        Args:
            pem (str): The PEM-encoded DH private key.

        Returns:
            DHPrivateKey: A DHPrivateKey instance initialized with the imported key.

        Raises:
            ValueError: If the PEM cannot be parsed as a valid DH private key.
        """
        try:
            key = pem_to_priv_key(pem)
            return cls(key["x"], DHParameters(key["p"], key["g"]))
        except Exception:
            raise ValueError("Could not parse PEM as private key")

    def _validate_peer(self, peer_y: int) -> None:
        p, q = self.params.p, self.params.q

        if not (2 <= peer_y <= p - 2):
            raise ValueError(f"Peer public value out of range: {peer_y}")

        if q and pow(peer_y, q, p) != 1:
            raise ValueError("Peer public not in subgroup defined by q")

    def _compute_raw_shared(self, peer_public: DHPublicKey) -> int:
        if (
            peer_public.params.p != self.params.p
            or peer_public.params.g != self.params.g
        ):
            raise ValueError("mismatched parameters")

        self._validate_peer(peer_public.y)
        z = pow(peer_public.y, self.x, self.params.p)

        return z
