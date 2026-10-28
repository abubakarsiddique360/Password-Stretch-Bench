"""Text reports for KDF measurements and crack estimates."""

from __future__ import annotations

import json

from .crack import CrackEstimate, format_duration, short_duration
from .kdf import Measurement, Params


def render_measurement(measurement: Measurement, *, title: str = "Measurement") -> str:
    lines = [title, "=" * 62]
    lines.append(f"kdf                  {measurement.params.label}")
    lines.append(f"per derivation       {format_duration(measurement.per_derivation)}")
    lines.append(f"derivations/second   {measurement.per_second:,.1f}")
    lines.append(f"best of              {measurement.repeats} runs of {measurement.batch}")
    return "\n".join(lines)


def render_table(measurements: list[Measurement]) -> str:
    header = f"{'profile':<26}{'per derivation':>16}{'per second':>14}{'vs fastest':>12}"
    lines = ["Cost of each profile on this machine", "=" * len(header), header]
    fastest = min(item.per_derivation for item in measurements)
    for item in measurements:
        lines.append(
            f"{item.params.label[:25]:<26}{format_duration(item.per_derivation):>16}"
            f"{item.per_second:>14,.0f}{item.per_derivation / fastest:>11.1f}x"
        )
    return "\n".join(lines)


def render_crack_matrix(
    measurements: list[Measurement],
    entropy_bits: list[int],
    attacker_rates: dict[str, float],
) -> str:
    bits = entropy_bits
    width = 12
    header = f"{'profile':<28}" + "".join(f"{f'{bit}b':>{width}}" for bit in bits)
    lines = [
        f"Time to crack one hash ({', '.join(attacker_rates)})",
        "=" * len(header),
        header,
    ]
    for item in measurements:
        rate = item.per_second * next(iter(attacker_rates.values()), 1.0)
        cells = ""
        for bit in bits:
            seconds = 2.0**bit / 2.0 / rate
            cells += f"{short_duration(seconds):>{width}}"
        lines.append(f"{item.params.label[:27]:<28}{cells}")
    lines.append("")
    lines.append("columns are password entropy in bits; y = years, ky = thousand years")
    return "\n".join(lines)


def render_attackers(
    measurements: list[Measurement], entropy_bits: int, attacker_rates: dict[str, float]
) -> str:
    width = 15
    header = f"{'profile':<26}" + "".join(f"{name:>{width}}" for name in attacker_rates)
    lines = [
        f"Time to crack a {entropy_bits}-bit password",
        "=" * len(header),
        header,
    ]
    for item in measurements:
        cells = ""
        for factor in attacker_rates.values():
            seconds = 2.0**entropy_bits / 2.0 / (item.per_second * factor)
            cells += f"{short_duration(seconds):>{width}}"
        lines.append(f"{item.params.label[:25]:<26}{cells}")
    return "\n".join(lines)


def render_estimate(estimate: CrackEstimate, *, label: str = "") -> str:
    lines = [f"Crack estimate{(' - ' + label) if label else ''}", "=" * 62]
    lines.append(f"entropy              {estimate.entropy_bits:g} bits")
    lines.append(f"key space            {estimate.keyspace:,.3e}")
    lines.append(f"guesses/second       {estimate.hashes_per_second:,.1f}")
    lines.append(f"expected time        {format_duration(estimate.seconds)}")
    return "\n".join(lines)


def render_profiles(profiles: list[Params]) -> str:
    lines = ["Profiles", "=" * 60]
    for params in profiles:
        lines.append(f"{params.label:<26}{params.kind}")
    return "\n".join(lines)


def render_json(payload) -> str:
    return json.dumps(payload, indent=2)


def render_scaling(measurements: list[Measurement]) -> str:
    """Ratio between measured cost and the model's linear prediction."""
    lines = ["Work factor vs measured cost", "=" * 66]
    lines.append(f"{'profile':<22}{'work factor':>14}{'ms':>10}{'ns per unit':>14}")
    for item in measurements:
        if item.params.kind != "pbkdf2-sha256":
            continue
        units = item.params.iterations
        lines.append(
            f"{item.params.label[:21]:<22}{units:>14,}{item.per_derivation * 1000:>10.1f}"
            f"{item.per_derivation * 1e9 / units:>14.1f}"
        )
    lines.append("")
    lines.append("a constant ns-per-iteration column means the cost is linear in the work factor")
    return "\n".join(lines)
