from dataclasses import dataclass
from secrets import randbelow
from typing import Literal, Self

from pycrypt.hash import hkdf
from pycrypt.asymmetric.dh.groups import GROUPS


def int_to_bytes(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


@dataclass(slots=True, frozen=True)
class DHParameters:
    p: int
    g: int
    q: int | None = None

    @classmethod
    def generate_parameters(
        cls, generator: int = 2, key_size: Literal[2048, 3072, 4096, 6144, 8192] = 2048
    ):
        if key_size not in GROUPS:
            raise ValueError("key_size must be only: 2048, 3072, 4096, 6144, or 8192")

        return cls(*GROUPS[key_size])

    def generate_private_key(self, bits: int | None = None) -> "DHPrivateKey":
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
    y: int
    params: DHParameters

    def to_bytes(self) -> bytes:
        return int_to_bytes(self.y)

    @staticmethod
    def from_bytes(b: bytes, params: DHParameters) -> Self:
        return DHPublicKey(bytes_to_int(b), params)


class DHPrivateKey:
    def __init__(self, x: int, params: DHParameters) -> None:
        self.x = x
        self.params = params

    def public_key(self) -> DHPublicKey:
        return DHPublicKey(pow(self.params.g, self.x, self.params.p), self.params)

    def exchange(
        self,
        peer_public: "DHPublicKey",
        *,
        info: bytes = b"",
        length: int = 32,
        salt: bytes | None = None,
    ) -> bytes:
        z = self._compute_raw_shared(peer_public)
        return hkdf(int_to_bytes(z), length, salt or b"", info)

    def zeroize(self) -> None:
        try:
            self.x = 0
        except Exception:
            pass

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
