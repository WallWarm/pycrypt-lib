import pytest
from dataclasses import FrozenInstanceError

from pycrypt.asymmetric import DHParameters, DHPrivateKey, DHPublicKey


def test_generate_parameters_supported_and_invalid():
    for size in (2048, 3072, 4096, 6144, 8192):
        params = DHParameters.generate_parameters(key_size=size)
        assert isinstance(params, DHParameters)
        assert params.p > 0 and params.g > 0

    with pytest.raises(ValueError):
        DHParameters.generate_parameters(key_size=1234)

def test_export_import_pem_roundtrip_private_and_public():
    params = DHParameters.generate_parameters()
    priv = params.generate_private_key()
    pub = priv.public_key()

    pem_priv = priv.export_key()
    assert isinstance(pem_priv, str) and pem_priv.strip() != ""

    imported_priv = DHPrivateKey.import_key(pem_priv)
    assert isinstance(imported_priv, DHPrivateKey)
    assert imported_priv.x == priv.x
    assert imported_priv.params.p == priv.params.p
    assert imported_priv.params.g == priv.params.g

    pem_pub = pub.export_key()
    assert isinstance(pem_pub, str) and pem_pub.strip() != ""

    imported_pub = DHPublicKey.import_key(pem_pub)
    assert isinstance(imported_pub, DHPublicKey)
    assert imported_pub.y == pub.y
    assert imported_pub.params.p == pub.params.p
    assert imported_pub.params.g == pub.params.g
