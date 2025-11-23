import base64
import textwrap

# --- ASN.1 Encoding / Decoding Primitives ---


def encode_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("Length must be non-negative")

    if length < 0x80:
        return bytes([length])

    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")

    return bytes([0x80 | len(length_bytes)]) + length_bytes


def decode_length(data: bytes, offset: int = 0) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("Offset out of range when decoding length")

    first = data[offset]
    offset += 1

    if first < 0x80:
        return first, offset

    nbytes = first & 0x7F

    if nbytes == 0:
        raise ValueError("Indefinite lengths are not allowed in DER")
    if offset + nbytes > len(data):
        raise ValueError("Insufficient data for length")

    length = int.from_bytes(data[offset : offset + nbytes], "big")
    offset += nbytes

    return length, offset


def encode_integer(n: int) -> bytes:
    if n < 0:
        raise ValueError("Only non-negative integers supported in this encoder")

    b = n.to_bytes((n.bit_length() + 7) // 8, "big") or b"\x00"

    if b[0] & 0x80:
        b = b"\x00" + b

    return b"\x02" + encode_length(len(b)) + b


def decode_integer(data: bytes, offset: int = 0) -> tuple[int, int]:
    if offset >= len(data) or data[offset] != 0x02:
        raise ValueError("Expected INTEGER tag (0x02)")

    offset += 1
    length, offset = decode_length(data, offset)
    if offset + length > len(data):
        raise ValueError("Insufficient bytes for INTEGER value")

    value = int.from_bytes(data[offset : offset + length], "big")
    offset += length

    return value, offset


def encode_sequence(*elements: bytes) -> bytes:
    content = b"".join(elements)
    return b"\x30" + encode_length(len(content)) + content


def decode_sequence(data: bytes, offset: int = 0) -> tuple[list[bytes], int]:
    if offset >= len(data) or data[offset] != 0x30:
        raise ValueError("Expected SEQUENCE tag (0x30)")

    length, payload_offset = decode_length(data, offset + 1)
    end = payload_offset + length
    if end > len(data):
        raise ValueError("SEQUENCE length exceeds available data")

    elements: list[bytes] = []
    cursor = payload_offset
    while cursor < end:
        if cursor >= len(data):
            raise ValueError("Unexpected end while decoding SEQUENCE elements")

        el_len, el_payload_offset = decode_length(data, cursor + 1)
        value_end = el_payload_offset + el_len

        if value_end > len(data):
            raise ValueError("Element length exceeds available data")

        elements.append(data[cursor:value_end])
        cursor = value_end

    return elements, end


# --- PEM / DER Conversion ---


def der_to_pem(der: bytes, label: str) -> str:
    b64 = base64.b64encode(der).decode("ascii")
    wrapped = "\n".join(textwrap.wrap(b64, 64))
    return f"-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n"


def pem_to_der(pem: str) -> bytes:
    lines = [line.strip() for line in pem.splitlines() if not line.startswith("-----")]
    return base64.b64decode("".join(lines))
