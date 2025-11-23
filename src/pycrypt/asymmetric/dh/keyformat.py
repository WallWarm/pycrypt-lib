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

# OID 1.2.840.113549.1.3.1  (dhKeyAgreement / PKCS#3)
DH_OID_BYTES: bytes = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x03\x01"


def encode_parameters(p: int, g: int, priv_len: int | None = None) -> bytes:
    """
    DHParameter ::= SEQUENCE {
        prime INTEGER, -- p
        base  INTEGER, -- g
        privateValueLength INTEGER OPTIONAL
    }
    """
    elems: list[bytes] = [encode_integer(p), encode_integer(g)]
    if priv_len is not None:
        elems.append(encode_integer(priv_len))
    return encode_sequence(*elems)


def decode_parameters(der: bytes) -> dict[str, int]:
    """
    Accepts a DER-encoded DHParameter SEQUENCE and returns dict { "p":..., "g":..., "privateValueLength": ... (optional) }
    """
    seq_elems, _ = decode_sequence(der)
    if len(seq_elems) < 2:
        raise ValueError("Invalid DHParameter sequence")
    p = decode_integer(seq_elems[0])[0]
    g = decode_integer(seq_elems[1])[0]
    res = {"p": p, "g": g}
    if len(seq_elems) >= 3:
        res["privateValueLength"] = decode_integer(seq_elems[2])[0]
    return res


# --- SPKI (X.509) DH Public Key ---


def encode_spki_pub_key(p: int, g: int, y: int, priv_len: int | None = None) -> bytes:
    """
    SubjectPublicKeyInfo with algorithmIdentifier containing DHParameter and the public value y encoded as INTEGER inside a BIT STRING.
    """
    alg_id = encode_sequence(DH_OID_BYTES, encode_parameters(p, g, priv_len))
    pub_der = encode_integer(y)  # public value as an INTEGER
    bit_string = b"\x03" + encode_length(len(pub_der) + 1) + b"\x00" + pub_der
    return encode_sequence(alg_id, bit_string)


def decode_spki_pub_key(der: bytes) -> dict[str, int]:
    """
    Parses a SubjectPublicKeyInfo for DH and returns dict { "p":..., "g":..., "y":..., "privateValueLength": ... (optional) }.
    """
    seq, _ = decode_sequence(der)
    if len(seq) < 2:
        raise ValueError("Invalid SubjectPublicKeyInfo; expected at least 2 elements")

    alg_seq_raw = seq[0]
    alg_seq_elems, _ = decode_sequence(alg_seq_raw)
    oid_bytes = alg_seq_elems[0]
    if oid_bytes[0] != 0x06:
        raise ValueError("Expected OID in AlgorithmIdentifier")
    if oid_bytes != DH_OID_BYTES:
        raise ValueError("Only PKCS#3 DH OID supported by this decoder")

    if len(alg_seq_elems) < 2:
        raise ValueError("Missing DH parameters in AlgorithmIdentifier")
    params_raw = alg_seq_elems[1]
    params = decode_parameters(params_raw)

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
    y = decode_integer(payload)[0]
    params["y"] = y
    return params


# --- PKCS#8 DH Private Key (wrap private integer x) ---


def encode_pkcs8_priv_key(p: int, g: int, x: int, priv_len: int | None = None) -> bytes:
    """
    PKCS#8 PrivateKeyInfo:
    PrivateKeyInfo ::= SEQUENCE {
        version Version,
        privateKeyAlgorithm AlgorithmIdentifier,
        privateKey OCTET STRING
        -- attributes OPTIONAL
    }
    For DH we put DHParameter in the AlgorithmIdentifier and an INTEGER x inside the OCTET STRING.
    """
    version = encode_integer(0)
    alg_id = encode_sequence(DH_OID_BYTES, encode_parameters(p, g, priv_len))
    privkey_der = encode_integer(x)  # private scalar encoded as INTEGER
    octet_string = b"\x04" + encode_length(len(privkey_der)) + privkey_der
    return encode_sequence(version, alg_id, octet_string)


def decode_pkcs8_priv_key(der: bytes) -> dict[str, int]:
    """
    Parse PKCS#8 PrivateKeyInfo for DH private keys.
    Returns { "p":..., "g":..., "x":..., "privateValueLength": ... (optional) }.
    """
    seq_elems, _ = decode_sequence(der)
    if len(seq_elems) < 3:
        raise ValueError("Invalid PKCS#8 structure")
    ver = decode_integer(seq_elems[0])[0]
    if ver != 0:
        raise ValueError("Unsupported PKCS#8 version")

    alg_seq_raw = seq_elems[1]
    alg_seq_elems, _ = decode_sequence(alg_seq_raw)
    oid_bytes = alg_seq_elems[0]
    if oid_bytes[0] != 0x06:
        raise ValueError("Expected OID in AlgorithmIdentifier")
    if oid_bytes != DH_OID_BYTES:
        raise ValueError("Only PKCS#3 DH OID supported in this decoder")
    if len(alg_seq_elems) < 2:
        raise ValueError("Missing DH parameters in AlgorithmIdentifier")
    params_raw = alg_seq_elems[1]
    params = decode_parameters(params_raw)

    octet = seq_elems[2]
    if octet[0] != 0x04:
        raise ValueError("Expected OCTET STRING for privateKey")
    length, off = decode_length(octet, 1)
    if off + length > len(octet):
        raise ValueError("OCTET STRING length exceeds available data")
    payload = octet[off : off + length]
    x = decode_integer(payload)[0]
    params["x"] = x
    return params


# --- Convenience PEM helpers for DH ---


def pub_key_to_pem(p: int, g: int, y: int, priv_len: int | None = None) -> str:
    der = encode_spki_pub_key(p, g, y, priv_len)
    return der_to_pem(der, "PUBLIC KEY")


def pem_to_pub_key(pem_text: str) -> dict[str, int]:
    der = pem_to_der(pem_text)
    return decode_spki_pub_key(der)


def priv_key_to_pem(p: int, g: int, x: int, priv_len: int | None = None) -> str:
    der = encode_pkcs8_priv_key(p, g, x, priv_len)
    return der_to_pem(der, "PRIVATE KEY")


def pem_to_priv_key(pem_text: str) -> dict[str, int]:
    der = pem_to_der(pem_text)
    return decode_pkcs8_priv_key(der)
