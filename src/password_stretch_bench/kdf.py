"""Key-derivation functions and how to time them honestly.

Two rules make the numbers in this project reproducible:

1. time a *batch* of derivations, never a single call, so the timer's resolution disappears;
2. take the **best** batch, not the mean, because the fastest run is the one least disturbed by
   the operating system's scheduler.

Everything here uses :mod:`hashlib` only - ``pbkdf2_hmac`` and ``scrypt`` are both in the standard
library, so the measurements are of the same primitives a real service would call.
"""

from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Callable
from dataclasses import dataclass

DEFAULT_PASSWORD = b"correct horse battery staple"
DEFAULT_SALT = b"0123456789abcdef"
DKLEN = 32


class KdfError(ValueError):
    """Raised for unsupported or impossible parameters."""


@dataclass(frozen=True)
class Params:
    kind: str
    iterations: int = 0
    memory_kib: int = 0
    parallelism: int = 1

    @property
    def label(self) -> str:
        if self.kind == "pbkdf2-sha256":
            return f"pbkdf2-sha256 {self.iterations:,}"
        if self.kind == "scrypt":
            return f"scrypt n=2^{int(math.log2(self.memory_kib))} r=8 p={self.parallelism}"
        return self.kind

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "iterations": self.iterations,
            "memory_kib": self.memory_kib,
            "parallelism": self.parallelism,
            "label": self.label,
        }


@dataclass(frozen=True)
class Measurement:
    params: Params
    seconds: float  # best observed time for one derivation
    repeats: int
    batch: int = 1

    @property
    def per_derivation(self) -> float:
        return self.seconds

    @property
    def per_second(self) -> float:
        return 1.0 / self.seconds if self.seconds else float("inf")

    def as_dict(self) -> dict:
        return {
            **self.params.as_dict(),
            "seconds": round(self.seconds, 6),
            "repeats": self.repeats,
            "batch": self.batch,
            "per_derivation_ms": round(self.per_derivation * 1000, 3),
            "per_second": round(self.per_second, 1),
        }


def derive(
    params: Params,
    *,
    password: bytes = DEFAULT_PASSWORD,
    salt: bytes = DEFAULT_SALT,
    dklen: int = DKLEN,
) -> bytes:
    if params.kind == "pbkdf2-sha256":
        if params.iterations < 1:
            raise KdfError("pbkdf2 needs at least one iteration")
        return hashlib.pbkdf2_hmac("sha256", password, salt, params.iterations, dklen)
    if params.kind == "scrypt":
        if params.memory_kib < 2:
            raise KdfError("scrypt needs a memory cost of at least 2 KiB")
        if params.memory_kib & (params.memory_kib - 1):
            raise KdfError("scrypt memory cost must be a power of two")
        return hashlib.scrypt(
            password,
            salt=salt,
            n=params.memory_kib,
            r=8,
            p=params.parallelism,
            dklen=dklen,
            # OpenSSL caps scrypt at 32 MiB by default, which rejects n=2^15 with r=8.
            maxmem=max(128 * params.memory_kib * 8 * 2, 64 * 1024 * 1024),
        )
    raise KdfError(f"unsupported kdf {params.kind!r}")


def measure(
    params: Params,
    *,
    repeats: int = 3,
    batch: int = 2,
    password: bytes = DEFAULT_PASSWORD,
    salt: bytes = DEFAULT_SALT,
    dklen: int = DKLEN,
    timer: Callable[[], float] = time.perf_counter,
) -> Measurement:
    """Best-of-``repeats`` timing of ``batch`` derivations, divided by the batch size."""
    best = float("inf")
    for _ in range(max(1, repeats)):
        start = timer()
        for _ in range(max(1, batch)):
            derive(params, password=password, salt=salt, dklen=dklen)
        elapsed = (timer() - start) / max(1, batch)
        best = min(best, elapsed)
    return Measurement(params=params, seconds=best, repeats=max(1, repeats),
                       batch=max(1, batch))


def calibrate(
    kind: str,
    target_seconds: float,
    *,
    low: int = 2_000,
    tolerance: float = 0.08,
    repeats: int = 2,
    timer: Callable[[], float] = time.perf_counter,
) -> Measurement:
    """Find the work factor that lands closest to ``target_seconds`` on this machine.

    Because both KDFs cost almost exactly proportional to their work factor, two or three
    measurements are enough: probe once, scale the factor by the ratio, then refine once if the
    machine hiccuped. A binary search would take more samples to learn less.
    """
    if target_seconds <= 0:
        raise KdfError("target must be positive")

    if kind == "scrypt":
        best: Measurement | None = None
        for power in range(1, 21):
            current = measure(
                Params("scrypt", memory_kib=1 << power, parallelism=1), repeats=repeats,
                batch=1, timer=timer
            )
            if best is None or abs(current.per_derivation - target_seconds) < abs(
                best.per_derivation - target_seconds
            ):
                best = current
            if current.per_derivation > target_seconds * (1 + tolerance):
                break
        assert best is not None
        return best

    probe = measure(Params(kind, iterations=max(1, low)), repeats=repeats, batch=1, timer=timer)
    if probe.per_derivation <= 0:
        raise KdfError("timer reported a non-positive duration")
    estimate = max(1, int(round(max(1, low) * target_seconds / probe.per_derivation)))
    best = measure(Params(kind, iterations=estimate), repeats=repeats, batch=1, timer=timer)
    for _ in range(3):
        if best.per_derivation <= 0:
            break
        scaled = int(best.params.iterations * target_seconds / best.per_derivation)
        if scaled == best.params.iterations:
            break
        candidate = measure(
            Params(kind, iterations=max(1, scaled)), repeats=repeats, batch=1, timer=timer
        )
        if abs(candidate.per_derivation - target_seconds) < abs(
            best.per_derivation - target_seconds
        ):
            best = candidate
        else:
            break
    return best
