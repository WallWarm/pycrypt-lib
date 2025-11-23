from pycrypt.utils.asn1 import (
    decode_integer,
    decode_length,
    decode_sequence,
    der_to_pem,
    encode_integer,
    encode_length,
    encode_sequence,
    pem_to_der,
)

# --- RSA Algorithm Identifier ---


RSA_OID_BYTES: bytes = (
    b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"  # OID 1.2.840.113549.1.1.1
)
NULL_BYTES: bytes = b"\x05\x00"


def encode_rsa_algorithm_identifier() -> bytes:
    return encode_sequence(RSA_OID_BYTES, NULL_BYTES)


# --- PKCS#1 RSA Key Encoding / Decoding Primitives ---


def encode_rsa_pub_key(n: int, e: int) -> bytes:
    return encode_sequence(encode_integer(n), encode_integer(e))


def decode_rsa_pub_key(der: bytes) -> dict[str, int]:
    elements, _ = decode_sequence(der)

    if len(elements) != 2:
        raise ValueError("Invalid RSA public key structure")

    n = decode_integer(elements[0])[0]
    e = decode_integer(elements[1])[0]

    return {"n": n, "e": e}


def encode_rsa_priv_key(
    n: int,
    e: int,
    d: int,
    p: int | None = None,
    q: int | None = None,
    dP: int | None = None,
    dQ: int | None = None,
    qInv: int | None = None,
) -> bytes:
    version = encode_integer(0)
    elems: list[bytes] = [
        version,
        encode_integer(n),
        encode_integer(e),
        encode_integer(d),
    ]

    if all(x is not None for x in (p, q, dP, dQ, qInv)):
        elems.extend(
            [
                encode_integer(p),  # pyright: ignore[reportArgumentType]
                encode_integer(q),  # pyright: ignore[reportArgumentType]
                encode_integer(dP),  # pyright: ignore[reportArgumentType]
                encode_integer(dQ),  # pyright: ignore[reportArgumentType]
                encode_integer(qInv),  # pyright: ignore[reportArgumentType]
            ]
        )

    return encode_sequence(*elems)


def decode_rsa_priv_key(der: bytes) -> dict[str, int]:
    elements, _ = decode_sequence(der)
    if len(elements) < 4:
        raise ValueError("RSAPrivateKey sequence too short")

    ints: list[int] = [decode_integer(e)[0] for e in elements[1:]]  # skip version
    res: dict[str, int] = {"n": ints[0], "e": ints[1], "d": ints[2]}

    if len(ints) >= 8:
        res.update(
            {
                "p": ints[3],
                "q": ints[4],
                "dP": ints[5],
                "dQ": ints[6],
                "qInv": ints[7],
            }
        )

    return res


# --- X.509 SPKI RSA Public Key Encoding / Decoding ---


def encode_spki_pub_key(n: int, e: int) -> bytes:
    alg_id = encode_rsa_algorithm_identifier()
    pubkey_der = encode_rsa_pub_key(n, e)
    bit_string = b"\x03" + encode_length(len(pubkey_der) + 1) + b"\x00" + pubkey_der

    return encode_sequence(alg_id, bit_string)


def decode_spki_pub_key(der: bytes) -> dict[str, int]:
    seq, _ = decode_sequence(der)
    if len(seq) < 2:
        raise ValueError("Invalid SubjectPublicKeyInfo; expected at least 2 elements")

    alg_seq, _ = decode_sequence(seq[0])
    oid_bytes = alg_seq[0]
    if oid_bytes[0] != 0x06:
        raise ValueError("Expected OID in AlgorithmIdentifier")
    if oid_bytes != RSA_OID_BYTES:
        raise ValueError("Only rsaEncryption OID supported by this decoder")

    bit_string = seq[1]
    if bit_string[0] != 0x03:
        raise ValueError("Expected BIT STRING for public key")

    bit_len, off = decode_length(bit_string, 1)
    if off >= len(bit_string):
        raise ValueError("BIT STRING truncated")

    unused_bits = bit_string[off]
    if unused_bits != 0x00:
        raise ValueError("Unsupported: BIT STRING has non-zero unused bits")

    payload = bit_string[off + 1 : off + bit_len]

    return decode_rsa_pub_key(payload)


# --- PKCS#8 helpers (wrap PKCS#1 inside PKCS#8) ---


def encode_pkcs8_priv_key(
    n: int,
    e: int,
    d: int,
    p: int | None = None,
    q: int | None = None,
    dP: int | None = None,
    dQ: int | None = None,
    qInv: int | None = None,
) -> bytes:
    version = encode_integer(0)
    alg_id = encode_rsa_algorithm_identifier()
    privkey_der = encode_rsa_priv_key(n, e, d, p, q, dP, dQ, qInv)
    bit_string = b"\x04" + encode_length(len(privkey_der)) + privkey_der

    return encode_sequence(version, alg_id, bit_string)


def decode_pkcs8_priv_key(der: bytes) -> dict[str, int]:
    seq_elems, _ = decode_sequence(der)
    if len(seq_elems) < 3:
        raise ValueError("Invalid PKCS#8 structure")

    ver = decode_integer(seq_elems[0])[0]
    if ver != 0:
        raise ValueError("Unsupported PKCS#8 version")

    alg_seq, _ = decode_sequence(seq_elems[1])
    oid_bytes = alg_seq[0]
    if oid_bytes[0] != 0x06:
        raise ValueError("Expected OID in AlgorithmIdentifier")
    if oid_bytes != RSA_OID_BYTES:
        raise ValueError("Only rsaEncryption OID supported in this decoder")

    octet = seq_elems[2]
    if octet[0] != 0x04:
        raise ValueError("Expected OCTET STRING for privateKey")

    length, off = decode_length(octet, 1)
    if off + length > len(octet):
        raise ValueError("OCTET STRING length exceeds available data")

    payload = octet[off : off + length]

    return decode_rsa_priv_key(payload)


# --- Convenience PEM helpers ---


def pub_key_to_pem(n: int, e: int) -> str:
    der = encode_spki_pub_key(n, e)
    return der_to_pem(der, "PUBLIC KEY")


def pem_to_pub_key(pem_text: str) -> dict[str, int]:
    der = pem_to_der(pem_text)
    return decode_spki_pub_key(der)


def priv_key_to_pem(
    n: int,
    e: int,
    d: int,
    p: int | None = None,
    q: int | None = None,
    dP: int | None = None,
    dQ: int | None = None,
    qInv: int | None = None,
) -> str:
    der = encode_pkcs8_priv_key(n, e, d, p, q, dP, dQ, qInv)
    return der_to_pem(der, "PRIVATE KEY")


def pem_to_priv_key(pem_text: str) -> dict[str, int]:
    der = pem_to_der(pem_text)
    return decode_pkcs8_priv_key(der)
