"""Regenerate README assets from real runs.

Usage:  python scripts/render_assets.py
Writes: docs/results.json, docs/images/bench.png,
        docs/images/cost-curves.png, docs/images/time-to-crack.svg
"""

from __future__ import annotations

import json
import math
import os
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from PIL import Image, ImageDraw, ImageFont  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from password_stretch_bench.crack import ATTACKER_RATES, format_duration  # noqa: E402
from password_stretch_bench.kdf import Params, calibrate, measure  # noqa: E402
from password_stretch_bench.report import (  # noqa: E402
    render_attackers,
    render_crack_matrix,
    render_measurement,
    render_scaling,
    render_table,
)

BG = "#0d1117"
CHROME = "#161b22"
FG = "#e6edf3"
MUTED = "#8b949e"
ACCENT = "#79c0ff"

PROFILES = [
    Params("pbkdf2-sha256", iterations=100_000),
    Params("pbkdf2-sha256", iterations=600_000),
    Params("pbkdf2-sha256", iterations=1_300_000),
    Params("scrypt", memory_kib=16_384, parallelism=1),
    Params("scrypt", memory_kib=32_768, parallelism=1),
]
ATTACKER = "1 GPU"


def load_font(size: int) -> ImageFont.FreeTypeFont:
    for name in ("consola.ttf", "cour.ttf", "DejaVuSansMono.ttf"):
        candidate = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / name
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


def render_terminal(text: str, out_path: Path, title: str) -> None:
    font = load_font(15)
    lines = text.expandtabs(4).splitlines() or [""]
    probe = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    char_width = probe.textlength("M", font=font)
    line_height = 21
    pad = 24
    width = int(max(len(line) for line in lines) * char_width) + pad * 2
    height = pad * 2 + len(lines) * line_height + 44
    image = Image.new("RGB", (max(width, 780), height), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle([0, 0, image.width, 34], fill=CHROME)
    for index, color in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        draw.ellipse([16 + index * 22, 10, 28 + index * 22, 22], fill=color)
    draw.text((92, 9), title, font=load_font(13), fill=MUTED)

    for row, line in enumerate(lines):
        color = FG
        stripped = line.strip()
        if line.startswith("$"):
            color = ACCENT
        elif stripped.startswith(("profile", "=", "-")) or "Cost of each" in stripped:
            color = MUTED
        elif stripped.endswith("x"):
            color = "#d29922"
        draw.text((pad, 50 + row * line_height), line, font=font, fill=color)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(out_path)


def render_cost_curves(measurements: list, out_path: Path) -> None:
    pbkdf2 = [item for item in measurements if item.params.kind == "pbkdf2-sha256"]
    scrypt = [item for item in measurements if item.params.kind == "scrypt"]

    figure, axis = plt.subplots(figsize=(9.4, 4.0))
    figure.patch.set_facecolor("#ffffff")
    axis.plot(
        [item.params.iterations for item in pbkdf2],
        [item.per_derivation * 1000 for item in pbkdf2],
        marker="o",
        color="#0969da",
        label="pbkdf2-sha256 (measured)",
    )
    smallest = pbkdf2[0]
    slope = smallest.per_derivation * 1000 / smallest.params.iterations
    axis.plot(
        [item.params.iterations for item in pbkdf2],
        [item.params.iterations * slope for item in pbkdf2],
        linestyle="--",
        color="#57606a",
        linewidth=1.1,
        label="linear reference through the 100k point",
    )
    axis.scatter(
        [item.params.memory_kib for item in scrypt],
        [item.per_derivation * 1000 for item in scrypt],
        marker="s",
        s=46,
        color="#8250df",
        label="scrypt (memory cost)",
        zorder=3,
    )
    for item in scrypt:
        axis.annotate(
            f"n=2^{int(math.log2(item.params.memory_kib))}",
            (item.params.memory_kib, item.per_derivation * 1000),
            textcoords="offset points",
            xytext=(6, -12),
            fontsize=7,
            color="#8250df",
        )
    axis.set_xscale("log")
    axis.set_yscale("log")
    axis.set_xlabel("work factor (pbkdf2 iterations, or scrypt memory cost in KiB)")
    axis.set_ylabel("milliseconds per derivation (log)")
    heading = "Cost is linear in the work factor - so the work factor is the knob"
    axis.set_title(heading, fontsize=10, loc="left")
    axis.grid(which="both", linestyle=":", alpha=0.45)
    axis.legend(fontsize=8, frameon=False, loc="upper left")
    for spine in ("top", "right"):
        axis.spines[spine].set_visible(False)
    figure.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(out_path, format="png", dpi=150)
    plt.close(figure)


def render_time_to_crack(measurements: list, out_path: Path) -> None:
    bits = list(range(30, 81, 5))
    factor = ATTACKER_RATES[ATTACKER]
    figure, axis = plt.subplots(figsize=(9.4, 4.0))
    figure.patch.set_facecolor("#ffffff")
    colours = ["#cf222e", "#d29922", "#1a7f37", "#0969da", "#8250df"]
    for colour, item in zip(colours, measurements, strict=False):
        rate = item.per_second * factor
        seconds = [2.0**bit / 2.0 / rate for bit in bits]
        axis.plot(bits, seconds, marker="o", markersize=3, color=colour,
                  label=f"{item.params.label} ({format_duration(item.per_derivation)})")
    axis.axhline(31_557_600 * 100, color="#57606a", linestyle=":", linewidth=1)
    axis.text(bits[0], 31_557_600 * 120, "100 years", fontsize=7, color="#57606a")
    axis.set_yscale("log")
    axis.set_xlabel("password entropy (bits)")
    axis.set_ylabel(f"expected time to crack (seconds, log) - attacker: {ATTACKER}")
    axis.set_title("Ten bits of entropy is worth a thousand times the work factor", fontsize=10,
                   loc="left")
    axis.grid(which="both", linestyle=":", alpha=0.4)
    axis.legend(fontsize=7, frameon=False, loc="lower right")
    for spine in ("top", "right"):
        axis.spines[spine].set_visible(False)
    figure.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(out_path, format=out_path.suffix.lstrip("."))
    plt.close(figure)


def main() -> int:
    images = ROOT / "docs" / "images"
    images.mkdir(parents=True, exist_ok=True)
    os.chdir(ROOT)

    measurements = [measure(params, repeats=3) for params in PROFILES]
    calibration = calibrate("pbkdf2-sha256", 0.25, repeats=2)
    scrypt_calibration = calibrate("scrypt", 0.25, repeats=2)

    payload = {
        "profiles": [item.as_dict() for item in measurements],
        "calibrated_pbkdf2": calibration.as_dict(),
        "calibrated_scrypt": scrypt_calibration.as_dict(),
        "attacker_rates": ATTACKER_RATES,
    }
    (ROOT / "docs" / "results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    terminal = (
        "$ stretch-bench select --profiles examples/profiles.json --attacker \"1 GPU\"\n\n"
        + render_table(measurements)
        + "\n\n"
        + render_scaling(measurements)
        + "\n\n"
        + render_attackers(measurements, 50, {ATTACKER: ATTACKER_RATES[ATTACKER]})
        + "\n\n$ stretch-bench calibrate --target-ms 250\n\n"
        + render_measurement(calibration, title="Calibrated to 250 ms")
        + "\n\n$ stretch-bench matrix --bits 40,50,60 --attacker \"8 GPU rig\"\n\n"
        + render_crack_matrix(
            measurements, [40, 50, 60], {"8 GPU rig": ATTACKER_RATES["8 GPU rig"]}
        )
    )
    title = "stretch-bench  -  measured cost, then the crack arithmetic"
    render_terminal(terminal, images / "bench.png", title)
    render_cost_curves(measurements, images / "cost-curves.png")
    render_time_to_crack(measurements, images / "time-to-crack.svg")

    summary = " | ".join(
        f"{item.params.label}={item.per_derivation * 1000:.1f}ms" for item in measurements
    )
    print(
        summary
        + f" | calibrated pbkdf2 {calibration.params.iterations:,} = "
        f"{calibration.per_derivation * 1000:.0f}ms"
        + f" | calibrated scrypt n=2^{int(math.log2(scrypt_calibration.params.memory_kib))} = "
        f"{scrypt_calibration.per_derivation * 1000:.0f}ms"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
