import pytest
from vault.sss import ShamirSSS
from vault.feldman import FeldmanVSS


@pytest.fixture
def sss_feldman():
    return ShamirSSS(), FeldmanVSS()


def test_valid_share_passes_verification(sss_feldman):
    sss, feldman = sss_feldman
    shares, coeffs = sss.split(b"test secret", 5, 3)
    commitments = feldman.generate_commitments(coeffs)
    for x, y in shares:
        assert feldman.verify_share(x, y, commitments), f"Share x={x} failed verification"


def test_tampered_share_fails_verification(sss_feldman):
    sss, feldman = sss_feldman
    shares, coeffs = sss.split(b"test secret", 5, 3)
    commitments = feldman.generate_commitments(coeffs)

    x, y = shares[0]
    assert not feldman.verify_share(x, y + 1, commitments), "Tampered y should fail"
    assert not feldman.verify_share(x, y - 1, commitments), "Tampered y should fail"


def test_commitments_length_equals_threshold(sss_feldman):
    sss, feldman = sss_feldman
    k = 4
    _, coeffs = sss.split(b"test", 6, k)
    commitments = feldman.generate_commitments(coeffs)
    assert len(commitments) == k


def test_wrong_x_fails_verification(sss_feldman):
    sss, feldman = sss_feldman
    shares, coeffs = sss.split(b"abc", 3, 2)
    commitments = feldman.generate_commitments(coeffs)

    x, y = shares[0]
    wrong_x = x + 1
    assert not feldman.verify_share(wrong_x, y, commitments)


def test_cross_share_fails_verification(sss_feldman):
    """A share from one split should fail against commitments from a different split."""
    sss, feldman = sss_feldman
    shares1, coeffs1 = sss.split(b"secret_one", 3, 2)
    shares2, coeffs2 = sss.split(b"secret_two", 3, 2)

    commitments1 = feldman.generate_commitments(coeffs1)
    x2, y2 = shares2[0]
    assert not feldman.verify_share(x2, y2, commitments1)
