from pycrypt.hash.sha.utils import MASK_32, Sigma_0, Sigma_1, ch, maj, sigma_0, sigma_1


class SHA256:
    _H0 = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ]

    _K = [
        0x428A2F98,
        0x71374491,
        0xB5C0FBCF,
        0xE9B5DBA5,
        0x3956C25B,
        0x59F111F1,
        0x923F82A4,
        0xAB1C5ED5,
        0xD807AA98,
        0x12835B01,
        0x243185BE,
        0x550C7DC3,
        0x72BE5D74,
        0x80DEB1FE,
        0x9BDC06A7,
        0xC19BF174,
        0xE49B69C1,
        0xEFBE4786,
        0x0FC19DC6,
        0x240CA1CC,
        0x2DE92C6F,
        0x4A7484AA,
        0x5CB0A9DC,
        0x76F988DA,
        0x983E5152,
        0xA831C66D,
        0xB00327C8,
        0xBF597FC7,
        0xC6E00BF3,
        0xD5A79147,
        0x06CA6351,
        0x14292967,
        0x27B70A85,
        0x2E1B2138,
        0x4D2C6DFC,
        0x53380D13,
        0x650A7354,
        0x766A0ABB,
        0x81C2C92E,
        0x92722C85,
        0xA2BFE8A1,
        0xA81A664B,
        0xC24B8B70,
        0xC76C51A3,
        0xD192E819,
        0xD6990624,
        0xF40E3585,
        0x106AA070,
        0x19A4C116,
        0x1E376C08,
        0x2748774C,
        0x34B0BCB5,
        0x391C0CB3,
        0x4ED8AA4A,
        0x5B9CCA4F,
        0x682E6FF3,
        0x748F82EE,
        0x78A5636F,
        0x84C87814,
        0x8CC70208,
        0x90BEFFFA,
        0xA4506CEB,
        0xBEF9A3F7,
        0xC67178F2,
    ]

    def __init__(self, data: bytes = b""):
        self._H = self._H0.copy()
        self._unprocessed = b""
        self._message_byte_length = 0
        if data:
            self.update(data)

    def reset(self):
        self._H = self._H0.copy()
        self._unprocessed = b""
        self._message_byte_length = 0

    def update(self, data: bytes):
        if not data:
            return
        self._message_byte_length += len(data)
        data = self._unprocessed + data
        block_count = len(data) // 64
        for i in range(block_count):
            self._process_block(data[i * 64 : (i + 1) * 64])
        self._unprocessed = data[block_count * 64 :]

    def _pad_message(self, message: bytes) -> bytes:
        bit_len = self._message_byte_length * 8
        message += b"\x80"
        while (len(message) * 8) % 512 != 448:
            message += b"\x00"
        message += bit_len.to_bytes(8, "big")
        return message

    def _parse_message(self, message: bytes):
        for i in range(0, len(message), 64):
            yield message[i : i + 64]

    def _prepare_message_schedule(self, block: bytes) -> list[int]:
        W = [0] * 64
        for i in range(64):
            if i < 16:
                W[i] = int.from_bytes(block[i * 4 : (i + 1) * 4], "big")
            else:
                W[i] = (
                    sigma_1(W[i - 2]) + W[i - 7] + sigma_0(W[i - 15]) + W[i - 16]
                ) & MASK_32
        return W

    def _process_block(self, block: bytes):
        W = self._prepare_message_schedule(block)
        a, b, c, d, e, f, g, h = self._H
        for t in range(64):
            T1 = (h + Sigma_1(e) + ch(e, f, g) + self._K[t] + W[t]) & MASK_32
            T2 = (Sigma_0(a) + maj(a, b, c)) & MASK_32
            h, g, f, e, d, c, b, a = (
                g,
                f,
                e,
                (d + T1) & MASK_32,
                c,
                b,
                a,
                (T1 + T2) & MASK_32,
            )

        self._H = [(x + y) & MASK_32 for x, y in zip(self._H, [a, b, c, d, e, f, g, h])]

    def _finalize(self):
        message = self._pad_message(self._unprocessed)
        for block in self._parse_message(message):
            self._process_block(block)

    def digest(self) -> bytes:
        state = (self._H.copy(), self._unprocessed, self._message_byte_length)
        self._finalize()
        digest_bytes = b"".join(h.to_bytes(4, "big") for h in self._H)
        self._H, self._unprocessed, self._message_byte_length = state
        return digest_bytes

    def hexdigest(self) -> str:
        return self.digest().hex()
