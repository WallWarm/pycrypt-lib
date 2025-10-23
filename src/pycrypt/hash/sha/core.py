from abc import ABC, abstractmethod


class SHA(ABC):
    block_size: int
    digest_size: int
    word_size: int
    MASK: int

    def __init__(self, data: bytes | None = None):
        self._buffer: bytes = b""
        self._message_byte_len: int = 0
        self._hash: list[int] = self._init_hash()

        if data:
            self.update(data)

    @classmethod
    @abstractmethod
    def _init_hash(cls) -> list[int]: ...

    @classmethod
    @abstractmethod
    def _get_constants(cls) -> list[int]: ...

    @abstractmethod
    def _process_block(self, block: bytes): ...

    @abstractmethod
    def _schedule_message(self, block: bytes) -> list[int]: ...

    def reset(self) -> None:
        self._buffer = b""
        self._message_byte_len = 0
        self._hash = self._init_hash()

    def update(self, data: bytes):
        if not data:
            return

        self._buffer += data
        self._message_byte_len += len(data)

        while len(self._buffer) >= self.block_size:
            block = self._buffer[: self.block_size]
            self._buffer = self._buffer[self.block_size :]
            self._process_block(block)

    def digest(self) -> bytes:
        state = self._hash.copy(), self._buffer, self._message_byte_len

        padded = self._pad_message()
        for block in self._parse_message(padded):
            self._process_block(block)

        digest_bytes = b"".join(H.to_bytes(4, "big") for H in self._hash)[
            : self.digest_size
        ]
        self._hash, self._buffer, self._message_byte_len = state

        return digest_bytes

    def hexdigest(self):
        return self.digest().hex()

    def _pad_message(self):
        message_bit_len = self._message_byte_len * 8
        buffer = self._buffer
        padding_len = (
            self.block_size - ((len(buffer) + 9) % self.block_size)
        ) % self.block_size
        padding = b"\x80" + b"\x00" * padding_len
        length = message_bit_len.to_bytes(8, "big")
        return buffer + padding + length

    @classmethod
    def _parse_message(cls, message: bytes):
        for i in range(0, len(message), cls.block_size):
            yield message[i : i + 64]
