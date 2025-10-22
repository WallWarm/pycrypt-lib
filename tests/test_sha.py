import pytest
from pycrypt.hash import sha256


@pytest.mark.parametrize(
    argnames="message,hash",
    argvalues=[
        (
            b"abc",
            bytes.fromhex(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            ),
        ),
        (
            b"",
            bytes.fromhex(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            bytes.fromhex(
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
            ),
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            bytes.fromhex(
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
            ),
        ),
    ],
)
def test_sha256_known_vector(message, hash):
    assert sha256(message) == hash
