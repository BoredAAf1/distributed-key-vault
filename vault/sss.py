"""
Shamir's Secret Sharing over F_p (secp256k1 field prime).

Secrets are prefixed with a 4-byte length header before conversion to a
field element so that leading-zero bytes round-trip correctly.
"""

from vault.randomness import RandomSource, get_random_source

# secp256k1 field prime — 256-bit safe prime
P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1

_MAX_SECRET_BYTES = 27  # 4-byte prefix + 27 bytes = 31 bytes << 256 bits, always < P


class ShamirSSS:
    def __init__(self, rng: RandomSource | None = None):
        self.P = P
        self.rng = rng or get_random_source()

    def split(
        self, secret: bytes, n: int, k: int
    ) -> tuple[list[tuple[int, int]], list[int]]:
        """
        Split *secret* into *n* shares with reconstruction threshold *k*.

        Returns (shares, coefficients) where coefficients are needed for
        Feldman VSS commitment generation.
        """
        if k < 2 or n < k:
            raise ValueError(f"Invalid parameters: need 2 <= k <= n, got k={k}, n={n}")
        if len(secret) > _MAX_SECRET_BYTES:
            raise ValueError(
                f"Secret too large: {len(secret)} bytes (max {_MAX_SECRET_BYTES}). "
                "Split a derived key instead of the raw secret."
            )

        # Build a fixed 32-byte payload: 4-byte length prefix + secret + zero
        # padding.  Trailing zeros are preserved by the integer round-trip
        # (they affect the integer's value), so the prefix stays at offset 0
        # when we decode with to_bytes(32) in reconstruct().
        payload = len(secret).to_bytes(4, "big") + secret
        padded = payload + b"\x00" * (32 - len(payload))
        secret_int = int.from_bytes(padded, "big")

        if secret_int >= self.P:
            raise ValueError(
                "Secret integer value exceeds prime field — reduce secret size."
            )

        # Polynomial a[0]=secret, a[1..k-1]=random
        coeffs = [secret_int] + [self.rng.randbelow(self.P) for _ in range(k - 1)]

        shares = [(i, self._poly_eval(coeffs, i, self.P)) for i in range(1, n + 1)]
        return shares, coeffs

    def reconstruct(self, shares: list[tuple[int, int]]) -> bytes:
        """Lagrange-interpolate at x=0 and decode the original secret bytes."""
        secret_int = self._lagrange_interpolate(shares, self.P)

        # Always decode to exactly 32 bytes (= 256-bit field width) so the
        # 4-byte length prefix stays at a fixed offset regardless of how many
        # leading-zero bytes the original payload had.
        data = secret_int.to_bytes(32, "big")

        original_length = int.from_bytes(data[:4], "big")
        end = 4 + original_length
        if original_length <= _MAX_SECRET_BYTES and end <= 32:
            return data[4:end]
        # Below-threshold reconstruction yields a garbage length field; return
        # raw bytes so callers can detect the mismatch.
        return data

    def _poly_eval(self, coeffs: list[int], x: int, p: int) -> int:
        """Horner's method evaluation of polynomial mod p."""
        result = 0
        for coeff in reversed(coeffs):
            result = (result * x + coeff) % p
        return result

    def _lagrange_interpolate(self, shares: list[tuple[int, int]], p: int) -> int:
        """Lagrange interpolation at x=0 over F_p."""
        k = len(shares)
        secret = 0
        for i in range(k):
            xi, yi = shares[i]
            numerator = 1
            denominator = 1
            for j in range(k):
                if i == j:
                    continue
                xj = shares[j][0]
                numerator = (numerator * (-xj)) % p
                denominator = (denominator * (xi - xj)) % p
            # Modular inverse via Fermat's little theorem (p is prime)
            lagrange_coeff = (numerator * pow(denominator, p - 2, p)) % p
            secret = (secret + yi * lagrange_coeff) % p
        return secret
