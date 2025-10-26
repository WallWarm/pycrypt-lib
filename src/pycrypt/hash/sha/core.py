from abc import ABC, abstractmethod


class SHACore(ABC):
    """Abstract base class for SHA-family hash functions.

    This class defines the core logic shared among SHA algorithms such as
    SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512. It provides message
    buffering, padding, and block processing flow, while leaving the
    algorithm-specific operations (like message schedule and compression)
    to subclasses.

    Subclasses must implement:
        - `_init_hash()`: Return the initial hash state values.
        - `_get_constants()`: Return the algorithm's round constants.
        - `_process_block(block)`: Process one 512-bit block of data.
        - `_schedule_message(block)`: Expand the input block into the message schedule.
    """

    BLOCK_SIZE: int
    DIGEST_SIZE: int
    WORD_SIZE: int
    _MASK: int

    def __init__(self, data: bytes | bytearray | None = None):
        """Initialize the SHA state.

        Args:
            data (bytes | None, optional): Optional initial data to hash.
                If provided, the instance automatically updates with it.
        """
        self._buffer: bytes = b""
        self._message_byte_len: int = 0
        self._hash: list[int] = self._init_hash()

        if data:
            self.update(data)

    # --- Digest ---

    def digest(self) -> bytes:
        """Return the hash digest of all processed data.

        This finalizes the current message with padding as per the SHA
        specification, processes any remaining blocks, and returns the
        resulting digest bytes.

        Returns:
            bytes: The binary hash digest.
        """
        state = self._hash.copy(), self._buffer, self._message_byte_len

        padded = self._pad_message()
        for block in self._parse_message(padded):
            self._process_block(block)

        digest_bytes = b"".join(H.to_bytes(4, "big") for H in self._hash)[
            : self.DIGEST_SIZE
        ]
        self._hash, self._buffer, self._message_byte_len = state

        return digest_bytes

    def hexdigest(self):
        """Return the digest as a hexadecimal string.

        Returns:
            str: Hexadecimal representation of the digest.
        """
        return self.digest().hex()

    def update(self, data: bytes | bytearray):
        """Update the hash with new data.

        Args:
            data (bytes): Input data to hash. May be called multiple times
                to process streaming input.
        """
        if not data:
            return

        self._buffer += data
        self._message_byte_len += len(data)

        while len(self._buffer) >= self.BLOCK_SIZE:
            block = self._buffer[: self.BLOCK_SIZE]
            self._buffer = self._buffer[self.BLOCK_SIZE :]
            self._process_block(block)

    def reset(self) -> None:
        """Reset the hashing state to its initial values."""
        self._buffer = b""
        self._message_byte_len = 0
        self._hash = self._init_hash()

    # --- PRIVATE: Hashing Logic ---

    def _pad_message(self):
        message_bit_len = self._message_byte_len * 8
        buffer = self._buffer
        padding_len = (
            self.BLOCK_SIZE - ((len(buffer) + 9) % self.BLOCK_SIZE)
        ) % self.BLOCK_SIZE
        padding = b"\x80" + b"\x00" * padding_len
        length = message_bit_len.to_bytes(8, "big")
        return buffer + padding + length

    @abstractmethod
    def _process_block(self, block: bytes): ...

    @abstractmethod
    def _schedule_message(self, block: bytes) -> list[int]: ...

    @classmethod
    def _parse_message(cls, message: bytes):
        for i in range(0, len(message), cls.BLOCK_SIZE):
            yield message[i : i + 64]

    # --- PRIVATE: Constants ---

    @classmethod
    @abstractmethod
    def _init_hash(cls) -> list[int]: ...

    @classmethod
    @abstractmethod
    def _get_constants(cls) -> list[int]: ...
