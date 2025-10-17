class PKCS7:
    @staticmethod
    def pad(data: bytes, block_size: int = 16) -> bytes:
        if block_size <= 0 or block_size > 255:
            raise ValueError("Invalid block size for PKCS#7")

        pad_len = block_size - (len(data) % block_size)

        return data + bytes([pad_len]) * pad_len

    @staticmethod
    def unpad(data: bytes, block_size: int = 16) -> bytes:
        if not data or len(data) % block_size != 0:
            raise ValueError("Invalid PKCS#7 padded data length")

        pad_len = data[-1]

        if (
            not 1 <= pad_len <= block_size
            or data[-pad_len:] != bytes([pad_len]) * pad_len
        ):
            raise ValueError("Invalid PKCS#7 padding")

        return data[:-pad_len]
