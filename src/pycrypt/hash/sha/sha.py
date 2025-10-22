from pycrypt.hash.sha.utils import MASK_32, Sigma_0, Sigma_1, ch, maj, sigma_0, sigma_1

_H = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]

K = [
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


def pad_message(message: bytes) -> bytes:
    bit_len = len(message) * 8
    message += b"\x80"
    while (len(message) * 8) % 512 != 448:
        message += b"\x00"
    message += bit_len.to_bytes(8, "big")
    return message


def parse_message(message: bytes):
    for i in range(0, len(message), 64):
        yield message[i : i + 64]


def prepare_message_schedule(block: bytes) -> list[int]:
    W = [0] * 64
    for t in range(64):
        if t < 16:
            W[t] = int.from_bytes(block[t * 4 : (t + 1) * 4], "big")
        else:
            W[t] = (
                sigma_1(W[t - 2]) + W[t - 7] + sigma_0(W[t - 15]) + W[t - 16]
            ) & MASK_32
    return W


def compress_block(block: bytes, H: list[int]) -> list[int]:
    W = prepare_message_schedule(block)
    a, b, c, d, e, f, g, h = H
    for t in range(64):
        T1 = (h + Sigma_1(e) + ch(e, f, g) + K[t] + W[t]) & MASK_32
        T2 = (Sigma_0(a) + maj(a, b, c)) & MASK_32
        h = g
        g = f
        f = e
        e = (d + T1) & MASK_32
        d = c
        c = b
        b = a
        a = (T1 + T2) & MASK_32

    return [
        (H[0] + a) & MASK_32,
        (H[1] + b) & MASK_32,
        (H[2] + c) & MASK_32,
        (H[3] + d) & MASK_32,
        (H[4] + e) & MASK_32,
        (H[5] + f) & MASK_32,
        (H[6] + g) & MASK_32,
        (H[7] + h) & MASK_32,
    ]


def sha256(data: bytes):
    message = pad_message(data)
    blocks = parse_message(message)
    hash = _H.copy()
    for block in blocks:
        hash = compress_block(block, hash)

    return bytes.fromhex("".join(f"{x:08x}" for x in hash))
