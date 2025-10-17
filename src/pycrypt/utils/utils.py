def xor_bytes(a: bytearray | bytes, b: bytearray | bytes) -> bytearray:
    return bytearray(x ^ y for x, y in zip(a, b))
