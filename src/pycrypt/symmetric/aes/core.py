from typing import Final

from pycrypt.utils import xor_bytes
from pycrypt.symmetric.aes.utils import (
    validate_len,
    GF_MUL_TABLES as _GMT,
    INV_SBOX,
    RCON,
    SBOX,
)


class AESCore:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes")

        self.KEY: Final[bytes] = key
        self.NK: Final[int] = len(key) // 4
        self.NR: Final[int] = {4: 10, 6: 12, 8: 14}[self.NK]
        self.ROUND_KEYS: Final[list[bytearray]] = self._key_expansion()

    # --- Encryption ---

    def cipher(self, plaintext: bytes | bytearray) -> bytes:
        validate_len("Plaintext", plaintext, 16)

        state = bytearray(plaintext)

        self._add_round_key(state, self.ROUND_KEYS[0])
        for round in range(1, self.NR + 1):
            self._sub_bytes(state)
            self._shift_rows(state)

            if round < self.NR:
                self._mix_columns(state)

            self._add_round_key(state, self.ROUND_KEYS[round])

        return bytes(state)

    def inv_cipher(self, ciphertext: bytes | bytearray) -> bytes:
        validate_len("Ciphertext", ciphertext, 16)

        state = bytearray(ciphertext)

        self._add_round_key(state, self.ROUND_KEYS[-1])
        for round in range(self.NR - 1, -1, -1):
            self.inv_shift_rows(state)
            self.inv_sub_bytes(state)
            self._add_round_key(state, self.ROUND_KEYS[round])

            if round > 0:
                self.inv_mix_columns(state)

        return bytes(state)

    # --- PRIVATE: In-Place Cipher Transformations ---

    def _sub_bytes(self, state: bytearray):
        for i in range(16):
            state[i] = SBOX[state[i]]

    def _shift_rows(self, state: bytearray):
        temp = state.copy()
        for r in range(4):
            for c in range(4):
                state[4 * c + r] = temp[4 * ((c + r) % 4) + r]

    def _mix_columns(self, state: bytearray):
        for c in range(4):
            (c0, c1, c2, c3) = [state[4 * c + r] for r in range(4)]
            state[4 * c + 0] = _GMT[0x02][c0] ^ _GMT[0x03][c1] ^ c2 ^ c3
            state[4 * c + 1] = c0 ^ _GMT[0x02][c1] ^ _GMT[0x03][c2] ^ c3
            state[4 * c + 2] = c0 ^ c1 ^ _GMT[0x02][c2] ^ _GMT[0x03][c3]
            state[4 * c + 3] = _GMT[0x03][c0] ^ c1 ^ c2 ^ _GMT[0x02][c3]

    def _add_round_key(self, state: bytearray, round_key: bytearray):
        for idx, k in enumerate(round_key):
            state[idx] ^= k

    # --- PRIVATE: In-Place Inverse Cipher Transformations ---

    def inv_shift_rows(self, state: bytearray):
        temp = state.copy()
        for r in range(4):
            for c in range(4):
                state[4 * c + r] = temp[4 * ((c - r) % 4) + r]

    def inv_sub_bytes(self, state: bytearray):
        for i in range(16):
            state[i] = INV_SBOX[state[i]]

    def inv_mix_columns(self, state: bytearray):
        for c in range(4):
            (c0, c1, c2, c3) = [state[4 * c + r] for r in range(4)]

            # fmt: off
            state[4*c + 0] = _GMT[0x0e][c0] ^ _GMT[0x0b][c1] ^ _GMT[0x0d][c2] ^ _GMT[0x09][c3]
            state[4*c + 1] = _GMT[0x09][c0] ^ _GMT[0x0e][c1] ^ _GMT[0x0b][c2] ^ _GMT[0x0d][c3]
            state[4*c + 2] = _GMT[0x0d][c0] ^ _GMT[0x09][c1] ^ _GMT[0x0e][c2] ^ _GMT[0x0b][c3]
            state[4*c + 3] = _GMT[0x0b][c0] ^ _GMT[0x0d][c1] ^ _GMT[0x09][c2] ^ _GMT[0x0e][c3]

    # --- PRIVATE: Key Expansion ---

    def _key_expansion(self) -> list[bytearray]:
        key_symbols = list(self.KEY)

        words = [bytearray(key_symbols[4 * i : 4 * (i + 1)]) for i in range(self.NK)]

        for i in range(self.NK, 4 * (self.NR + 1)):
            temp = bytearray(words[i - 1])

            if i % self.NK == 0:
                temp = bytearray(SBOX[b] for b in AESCore._rot_word(temp))
                temp[0] ^= RCON[(i // self.NK) - 1]
            elif self.NK > 6 and i % self.NK == 4:
                temp = bytearray(SBOX[temp[j]] for j in range(4))

            words.append(xor_bytes(words[i - self.NK], temp))

        return [
            bytearray().join(words[4 * r : 4 * (r + 1)]) for r in range(self.NR + 1)
        ]

    # --- PRIVATE: Helper Functions ---

    @staticmethod
    def _rot_word(word: bytearray) -> bytearray:
        return bytearray(word[1:] + word[:1])

    # Mathematical Voodoo
    @staticmethod
    def _gf_mul(x: int, y: int) -> int:
        p = 0
        for _ in range(8):
            if y & 1:
                p ^= x
            high_bit_set = x & 0x80
            x <<= 1
            if high_bit_set:
                x ^= 0x1B
            x &= 0xFF
            y >>= 1
        return p

    def __del__(self):
        self.KEY = b"\x00" * len(self.KEY)  # pyright: ignore[reportConstantRedefinition, reportAttributeAccessIssue]
