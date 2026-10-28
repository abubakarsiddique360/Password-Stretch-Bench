"""Turn a measured derivation cost into a time-to-crack estimate."""

from __future__ import annotations

import math
from dataclasses import dataclass

SECONDS_PER = {
    "second": 1,
    "minute": 60,
    "hour": 3_600,
    "day": 86_400,
    "month": 2_592_000,
    "year": 31_557_600,
}

# An attacker guessing a leaked hash is not limited to one core: a single high-end GPU runs
# millions of PBKDF2-SHA256 guesses per second, a rented cluster more. These are the assumptions
# the estimate is built on, and they are the part everybody should argue about.
ATTACKER_RATES = {
    "single core": 1.0,
    "8-core CPU": 8.0,
    "1 GPU": 3_000.0,
    "8 GPU rig": 24_000.0,
    "rented cluster": 250_000.0,
}


@dataclass(frozen=True)
class CrackEstimate:
    entropy_bits: float
    hashes_per_second: float
    seconds: float

    @property
    def keyspace(self) -> float:
        return 2.0**self.entropy_bits

    @property
    def years(self) -> float:
        return self.seconds / SECONDS_PER["year"]

    def as_dict(self) -> dict:
        return {
            "entropy_bits": self.entropy_bits,
            "hashes_per_second": self.hashes_per_second,
            "seconds": self.seconds,
            "human": format_duration(self.seconds),
            "years": self.years,
        }


def crack_time(entropy_bits: float, hashes_per_second: float) -> CrackEstimate:
    """Expected time to brute force a key space of ``2**entropy_bits`` at a given guess rate.

    The expected number of guesses is half the key space, which is what a uniform random attacker
    needs on average.
    """
    if entropy_bits < 0:
        raise ValueError("entropy must be non-negative")
    if hashes_per_second <= 0:
        raise ValueError("hash rate must be positive")
    keyspace = 2.0**entropy_bits
    return CrackEstimate(
        entropy_bits=entropy_bits,
        hashes_per_second=hashes_per_second,
        seconds=keyspace / 2.0 / hashes_per_second,
    )


def format_duration(seconds: float) -> str:
    if seconds != seconds or seconds in (float("inf"), float("-inf")):
        return "never"
    if seconds < 1e-6:
        return f"{seconds * 1e9:.0f} ns"
    if seconds < 1e-3:
        return f"{seconds * 1e6:.0f} us"
    if seconds < 1:
        return f"{seconds * 1e3:.0f} ms"
    for unit in ("year", "month", "day", "hour", "minute"):
        size = SECONDS_PER[unit]
        if seconds >= size:
            value = seconds / size
            if value > 1e15:
                return f"{value:.1e} {unit}s"
            if value >= 1000:
                return f"{value:,.0f} {unit}s"
            return f"{value:.1f} {unit}s"
    return f"{seconds:.1f} s"


def short_duration(seconds: float) -> str:
    """Compact duration for narrow table cells: ``241y``, ``2.9mo``, ``1.4My``."""
    if seconds != seconds or seconds in (float("inf"), float("-inf")):
        return "never"
    year = SECONDS_PER["year"]
    if seconds >= year:
        years = seconds / year
        if years >= 1e9:
            return f"{years:.1e}y"
        if years >= 1e6:
            return f"{years / 1e6:.1f}My"
        if years >= 1e3:
            return f"{years / 1e3:.1f}ky"
        return f"{years:.0f}y" if years >= 10 else f"{years:.1f}y"
    for unit, size in (("mo", SECONDS_PER["month"]), ("d", SECONDS_PER["day"]),
                       ("h", SECONDS_PER["hour"]), ("m", SECONDS_PER["minute"])):
        if seconds >= size:
            return f"{seconds / size:.0f}{unit}"
    if seconds >= 1:
        return f"{seconds:.0f}s"
    if seconds >= 1e-3:
        return f"{seconds * 1e3:.0f}ms"
    return f"{seconds * 1e6:.0f}us"


def weakest_link(entropy_bits: float, rate: float, target_years: float) -> float:
    """Entropy needed to survive ``target_years`` at ``rate`` guesses per second."""
    if target_years <= 0 or rate <= 0:
        raise ValueError("target and rate must be positive")
    needed = 2.0 * rate * target_years * SECONDS_PER["year"]
    return math.log2(needed)


def human_password_entropy(charset_size: int, length: int) -> float:
    """Information content of a password drawn uniformly from a charset."""
    if charset_size < 2 or length < 1:
        raise ValueError("charset must be >= 2 and length >= 1")
    return length * math.log2(charset_size)
