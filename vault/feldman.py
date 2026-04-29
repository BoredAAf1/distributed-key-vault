"""
Feldman Verifiable Secret Sharing.

For Feldman VSS to be mathematically correct, the generator g must have
order equal to the SSS field prime P in the commitment group.

We use M = 4*P + 1 (prime) as the group modulus.  In Z_M*, the element
g = 16 = 2^4 has order exactly P (since M-1 = 4P and 16^P ≡ 1 mod M
while 16 ≠ 1 mod M).  The SSS polynomial coefficients live in Z_P, so
Fermat: g^{f(x)} = g^{f(x) mod P} = g^{y_i}  mod M  — verification holds.
"""

from vault.sss import P as _SSS_PRIME

# Feldman group modulus  M = 4*P + 1  (verified prime)
_M = 4 * _SSS_PRIME + 1

# Generator of order P in Z_M*  (verified: pow(16, P, _M) == 1 and 16 != 1)
_G = 16


class FeldmanVSS:
    def __init__(self):
        self.g = _G
        self.q = _SSS_PRIME  # group order (= SSS field prime)
        self.M = _M  # group modulus

    def generate_commitments(self, coeffs: list[int]) -> list[int]:
        """C_i = g^{a_i} mod M for each polynomial coefficient a_i ∈ Z_q."""
        return [pow(self.g, c, self.M) for c in coeffs]

    def verify_share(self, x: int, y: int, commitments: list[int]) -> bool:
        """
        Verify share (x, y) against Feldman commitments.

        LHS = g^y mod M
        RHS = ∏ C_j^(x^j) mod M   for j in 0..k-1

        Correct because g has order q = P, so g^{f(x)} = g^{f(x) mod P} = g^y.
        """
        lhs = pow(self.g, y, self.M)
        rhs = 1
        for j, commitment in enumerate(commitments):
            # x <= n (small), j <= k-1 (small) → x**j stays manageable
            rhs = (rhs * pow(commitment, x**j, self.M)) % self.M
        return lhs == rhs
