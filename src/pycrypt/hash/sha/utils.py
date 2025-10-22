MASK_32 = 0xFFFFFFFF


def rotr(x: int, n: int, w: int = 32) -> int:
    n = n % w
    return (x >> n) | ((x << w - n) & MASK_32)


def rotl(x: int, n: int, w: int = 32):
    n = n % w
    return ((x << n) & MASK_32) | (x >> w - n)


def shr(x: int, n: int):
    return x >> n


def ch(x: int, y: int, z: int):
    # Ch(x, y, z) = (x AND y) XOR ((NOT x) AND z)
    return ((x & y) ^ ((~x & MASK_32) & z)) & MASK_32


def maj(x: int, y: int, z: int):
    # Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
    return ((x & y) ^ (x & z) ^ (y & z)) & MASK_32


def Sigma_0(x: int):
    return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)) & MASK_32


def Sigma_1(x: int):
    return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)) & MASK_32


def sigma_0(x: int):
    return (rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)) & MASK_32


def sigma_1(x: int):
    return (rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)) & MASK_32
