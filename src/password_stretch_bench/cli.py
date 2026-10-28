"""Command line entry point for stretch-bench."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .crack import (
    ATTACKER_RATES,
    crack_time,
    format_duration,
    human_password_entropy,
    weakest_link,
)
from .kdf import KdfError, Params, calibrate, measure
from .report import (
    render_attackers,
    render_crack_matrix,
    render_estimate,
    render_json,
    render_measurement,
    render_profiles,
    render_scaling,
    render_table,
)


def _params_from_args(args) -> Params:
    if args.kind == "scrypt":
        return Params("scrypt", memory_kib=args.memory, parallelism=args.parallelism)
    return Params(args.kind, iterations=args.iterations)


def _load_profiles(path: str) -> list[Params]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    profiles = []
    for entry in payload.get("profiles", []):
        profiles.append(
            Params(
                kind=str(entry["kind"]),
                iterations=int(entry.get("iterations", 0)),
                memory_kib=int(entry.get("memory_kib", 0)),
                parallelism=int(entry.get("parallelism", 1)),
            )
        )
    if not profiles:
        raise KdfError(f"no profiles in {path}")
    return profiles


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stretch-bench",
        description="Measure password-hashing cost and turn it into time-to-crack.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    one = sub.add_parser("measure", help="time one parameter set")
    one.add_argument("--kind", choices=("pbkdf2-sha256", "scrypt"), default="pbkdf2-sha256")
    one.add_argument("--iterations", type=int, default=600_000)
    one.add_argument("--memory", type=int, default=32768, help="scrypt memory cost in KiB")
    one.add_argument("--parallelism", type=int, default=1)
    one.add_argument("--repeats", type=int, default=3)
    one.add_argument("--format", choices=("text", "json"), default="text")

    cal = sub.add_parser("calibrate", help="find the work factor that hits a target duration")
    cal.add_argument("--kind", choices=("pbkdf2-sha256", "scrypt"), default="pbkdf2-sha256")
    cal.add_argument("--target-ms", type=float, default=250.0)
    cal.add_argument("--repeats", type=int, default=2)

    sel = sub.add_parser("select", help="time every profile in a file")
    sel.add_argument("--profiles", default="examples/profiles.json")
    sel.add_argument("--repeats", type=int, default=2)
    sel.add_argument("--attacker", choices=tuple(ATTACKER_RATES), default="1 GPU")
    sel.add_argument("--entropy", type=int, default=50)
    sel.add_argument("--format", choices=("text", "json"), default="text")

    mat = sub.add_parser("matrix", help="crack-time grid of profiles against password entropy")
    mat.add_argument("--profiles", default="examples/profiles.json")
    mat.add_argument("--repeats", type=int, default=2)
    mat.add_argument("--bits", default="30,40,50,60,70,80")
    mat.add_argument("--attacker", choices=tuple(ATTACKER_RATES), default="1 GPU")

    crack = sub.add_parser("crack", help="time-to-crack for an entropy/rate pair")
    crack.add_argument("--entropy", type=float, required=True)
    crack.add_argument("--rate", type=float, default=3_000.0, help="guesses per second")
    crack.add_argument("--format", choices=("text", "json"), default="text")

    need = sub.add_parser("required-entropy", help="entropy needed to survive a target")
    need.add_argument("--that-many-years", type=float, default=10.0)
    need.add_argument("--attacker", choices=tuple(ATTACKER_RATES), default="8 GPU rig")
    need.add_argument("--kind", choices=("pbkdf2-sha256", "scrypt"), default="pbkdf2-sha256")
    need.add_argument("--iterations", type=int, default=600_000)
    need.add_argument("--memory", type=int, default=32768)

    pw = sub.add_parser("password", help="entropy of a uniformly random password")
    pw.add_argument("--charset", type=int, default=94)
    pw.add_argument("--length", type=int, required=True)

    sub.add_parser("attackers", help="list the attacker rate assumptions")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "attackers":
        for name, rate in ATTACKER_RATES.items():
            print(f"{name:<18}{rate:>12,.0f}x a single core")
        print()
        print("rates are multipliers over the measured single-core derivation rate.")
        return 0

    if args.command == "password":
        try:
            bits = human_password_entropy(args.charset, args.length)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"charset {args.charset} x length {args.length} = {bits:.1f} bits of entropy")
        return 0

    if args.command == "crack":
        estimate = crack_time(args.entropy, args.rate)
        if args.format == "json":
            print(render_json(estimate.as_dict()))
        else:
            print(render_estimate(estimate))
        return 0

    if args.command in ("measure", "calibrate"):
        try:
            if args.command == "calibrate":
                measurement = calibrate(
                    args.kind, args.target_ms / 1000.0, repeats=args.repeats
                )
                title = f"Calibrated to {args.target_ms:g} ms"
            else:
                measurement = measure(_params_from_args(args), repeats=args.repeats)
                title = "Measurement"
        except KdfError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.command == "measure" and args.format == "json":
            print(render_json(measurement.as_dict()))
        else:
            print(render_measurement(measurement, title=title))
        return 0

    if args.command == "select":
        try:
            profiles = _load_profiles(args.profiles)
        except (OSError, json.JSONDecodeError, KdfError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        measurements = [measure(params, repeats=args.repeats) for params in profiles]
        if args.format == "json":
            print(render_json([item.as_dict() for item in measurements]))
            return 0
        print(render_profiles(profiles))
        print()
        print(render_table(measurements))
        print()
        print(render_scaling(measurements))
        print()
        attackers = {args.attacker: ATTACKER_RATES[args.attacker]}
        print(render_attackers(measurements, args.entropy, attackers))
        return 0

    if args.command == "matrix":
        try:
            profiles = _load_profiles(args.profiles)
            bits = [int(part) for part in args.bits.split(",") if part.strip()]
        except (OSError, json.JSONDecodeError, KdfError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        measurements = [measure(params, repeats=args.repeats) for params in profiles]
        rates = {args.attacker: ATTACKER_RATES[args.attacker]}
        print(render_crack_matrix(measurements, bits, rates))
        return 0

    if args.command == "required-entropy":
        params = (
            Params("scrypt", memory_kib=args.memory)
            if args.kind == "scrypt"
            else Params(args.kind, iterations=args.iterations)
        )
        measurement = measure(params, repeats=2)
        rate = measurement.per_second * ATTACKER_RATES[args.attacker]
        needed = weakest_link(1.0, rate, args.that_many_years)
        print(f"profile        {params.label}  ({format_duration(measurement.per_derivation)})")
        print(f"attacker       {args.attacker}  ({rate:,.0f} guesses/second)")
        print(f"target         {args.that_many_years:g} years")
        print(f"needed         {needed:.1f} bits of password entropy")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
