def xor_bytes(a: bytearray, b: bytearray) -> bytearray:
    return bytearray(x ^ y for x, y in zip(a, b))
