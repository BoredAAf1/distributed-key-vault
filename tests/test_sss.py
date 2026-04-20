import pytest
from vault.sss import ShamirSSS


@pytest.fixture
def sss():
    return ShamirSSS()


def test_split_reconstruct_exact_threshold(sss):
    secret = b"hello world"
    shares, _ = sss.split(secret, 5, 3)
    assert sss.reconstruct(shares[:3]) == secret


def test_split_reconstruct_more_than_threshold(sss):
    secret = b"hello world"
    shares, _ = sss.split(secret, 5, 3)
    assert sss.reconstruct(shares) == secret  # all 5 shares


def test_reconstruct_fails_below_threshold(sss):
    secret = b"hello world"
    shares, _ = sss.split(secret, 5, 3)
    # With only 2 shares (< k=3) Lagrange interpolation yields a different polynomial
    wrong = sss.reconstruct(shares[:2])
    assert wrong != secret


def test_different_secrets_give_different_shares(sss):
    shares1, _ = sss.split(b"secret_alpha", 5, 3)
    shares2, _ = sss.split(b"secret_beta", 5, 3)
    # At least the y values should differ
    assert [y for _, y in shares1] != [y for _, y in shares2]


def test_large_secret_bytes(sss):
    secret = b"X" * 25  # 25 bytes + 4-byte prefix = 29 bytes (232 bits) << P
    shares, _ = sss.split(secret, 5, 3)
    assert sss.reconstruct(shares[:3]) == secret


def test_invalid_parameters_raise(sss):
    with pytest.raises(ValueError):
        sss.split(b"secret", n=2, k=3)  # k > n

    with pytest.raises(ValueError):
        sss.split(b"secret", n=5, k=1)  # k < 2


def test_non_contiguous_shares(sss):
    """Reconstruction works with any k-subset, not just the first k shares."""
    secret = b"non contiguous"
    shares, _ = sss.split(secret, 5, 3)
    # Use shares at indices 0, 2, 4 (x=1, 3, 5)
    subset = [shares[0], shares[2], shares[4]]
    assert sss.reconstruct(subset) == secret
