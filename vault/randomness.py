"""
Randomness providers for vault operations.

The default provider uses the operating system CSPRNG. The quantum provider is
opt-in and imports Qiskit lazily so normal runs do not require Qiskit to be
installed.
"""

import os
import secrets
from typing import Protocol


class RandomSource(Protocol):
    def random_bytes(self, length: int) -> bytes:
        """Return *length* random bytes."""

    def randbelow(self, upper_bound: int) -> int:
        """Return a random integer in [0, upper_bound)."""

    def token_hex(self, nbytes: int) -> str:
        """Return *nbytes* random bytes encoded as hex."""


class SystemRandomSource:
    """Random source backed by Python's standard cryptographic RNG APIs."""

    def random_bytes(self, length: int) -> bytes:
        return os.urandom(length)

    def randbelow(self, upper_bound: int) -> int:
        return secrets.randbelow(upper_bound)

    def token_hex(self, nbytes: int) -> str:
        return secrets.token_hex(nbytes)


class QuantumRandomSource:
    """Random source backed by Hadamard-basis measurements in Qiskit."""

    _MAX_SHOTS_PER_CIRCUIT = 4096

    def __init__(self):
        try:
            from qiskit import QuantumCircuit
            from qiskit.providers.basic_provider import BasicProvider
        except ImportError as exc:
            raise RuntimeError(
                "Quantum random generation requires qiskit. "
                "Install it with: pip install qiskit"
            ) from exc

        self._quantum_circuit_cls = QuantumCircuit
        self._backend = BasicProvider().get_backend("basic_simulator")

    def random_bytes(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""

        value = self._random_bits(length * 8)
        return value.to_bytes(length, "big")

    def randbelow(self, upper_bound: int) -> int:
        if upper_bound <= 0:
            raise ValueError("upper_bound must be positive")

        bit_length = upper_bound.bit_length()
        while True:
            value = self._random_bits(bit_length)
            if value < upper_bound:
                return value

    def token_hex(self, nbytes: int) -> str:
        return self.random_bytes(nbytes).hex()

    def _random_bits(self, bit_count: int) -> int:
        if bit_count < 0:
            raise ValueError("bit_count must be non-negative")
        if bit_count == 0:
            return 0

        chunks: list[str] = []
        remaining = bit_count
        while remaining:
            chunk_size = min(remaining, self._MAX_SHOTS_PER_CIRCUIT)
            chunks.append(self._measure_bits(chunk_size))
            remaining -= chunk_size

        bit_string = "".join(chunks)
        return int(bit_string, 2)

    def _measure_bits(self, bit_count: int) -> str:
        circuit = self._quantum_circuit_cls(1, 1)
        circuit.h(0)
        circuit.measure(0, 0)

        job = self._backend.run(circuit, shots=bit_count, memory=True)
        memory = job.result().get_memory(circuit)
        return "".join(item.replace(" ", "")[-1] for item in memory)


def get_random_source(use_quantum: bool = False) -> RandomSource:
    if use_quantum:
        return QuantumRandomSource()
    return SystemRandomSource()
