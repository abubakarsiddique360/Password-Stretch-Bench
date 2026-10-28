import json

import pytest

from password_stretch_bench.cli import main
from password_stretch_bench.crack import (
    ATTACKER_RATES,
    SECONDS_PER,
    crack_time,
    format_duration,
    human_password_entropy,
    weakest_link,
)
from password_stretch_bench.kdf import Measurement, Params
from password_stretch_bench.report import (
    render_attackers,
    render_crack_matrix,
    render_estimate,
    render_json,
    render_measurement,
    render_profiles,
    render_scaling,
    render_table,
)

SAMPLE = [
    Measurement(Params("pbkdf2-sha256", iterations=100_000), 0.036, 3, 2),
    Measurement(Params("pbkdf2-sha256", iterations=600_000), 0.247, 3, 2),
    Measurement(Params("scrypt", memory_kib=32768), 0.089, 3, 2),
]


def test_zero_entropy_is_half_a_guess():
    estimate = crack_time(0, 1000.0)
    assert estimate.seconds == pytest.approx(0.0005)


def test_crack_time_scales_with_entropy():
    slow = crack_time(40, 1000.0)
    fast = crack_time(60, 1000.0)
    assert fast.seconds == pytest.approx(slow.seconds * 2**20)


def test_crack_time_rejects_bad_input():
    with pytest.raises(ValueError):
        crack_time(-1, 1000.0)
    with pytest.raises(ValueError):
        crack_time(40, 0)


def test_years_property():
    estimate = crack_time(40, 3_000.0)
    assert estimate.years == pytest.approx(estimate.seconds / SECONDS_PER["year"])


def test_format_duration_units():
    assert format_duration(0.0000005) == "500 ns"
    assert format_duration(0.0005) == "500 us"
    assert format_duration(0.5) == "500 ms"
    assert format_duration(90) == "1.5 minutes"
    assert format_duration(7200) == "2.0 hours"
    assert format_duration(86400 * 3) == "3.0 days"
    assert format_duration(1e30).endswith("years")


def test_format_duration_handles_infinities():
    assert format_duration(float("inf")) == "never"


def test_weakest_link_inverts_crack_time():
    rate = 12_345.0
    bits = weakest_link(1.0, rate, 10.0)
    assert crack_time(bits, rate).years == pytest.approx(10.0)


def test_weakest_link_rejects_bad_input():
    with pytest.raises(ValueError):
        weakest_link(1.0, 0, 10.0)


def test_human_password_entropy():
    assert human_password_entropy(94, 8) == pytest.approx(52.44, abs=0.01)
    with pytest.raises(ValueError):
        human_password_entropy(1, 8)


def test_estimate_serialises():
    payload = json.loads(render_json(crack_time(50, 3000).as_dict()))
    assert payload["entropy_bits"] == 50
    assert payload["human"].endswith("years")


def test_render_measurement():
    text = render_measurement(SAMPLE[0])
    assert "derivations/second" in text
    assert "pbkdf2" in text


def test_render_table_shows_relative_cost():
    text = render_table(SAMPLE)
    assert "vs fastest" in text
    assert "1.0x" in text


def test_render_scaling_only_covers_pbkdf2():
    text = render_scaling(SAMPLE)
    assert "ns per unit" in text
    assert "scrypt" not in text


def test_render_crack_matrix_has_a_column_per_entropy():
    text = render_crack_matrix(SAMPLE, [30, 50, 70], {"1 GPU": 3000.0})
    assert "30b" in text and "70b" in text


def test_render_attackers_one_column_per_attacker():
    text = render_attackers(SAMPLE, 50, {"single core": 1.0, "1 GPU": 3000.0})
    assert "single core" in text and "1 GPU" in text


def test_render_estimate_fields():
    text = render_estimate(crack_time(50, 3000), label="demo")
    assert "Crack estimate - demo" in text
    assert "key space" in text


def test_render_profiles_lists_labels():
    text = render_profiles([item.params for item in SAMPLE])
    assert "scrypt n=2^15" in text


def test_cli_crack(capsys):
    assert main(["crack", "--entropy", "50", "--rate", "3000"]) == 0
    assert "expected time" in capsys.readouterr().out


def test_cli_crack_json(capsys):
    assert main(["crack", "--entropy", "50", "--rate", "3000", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["entropy_bits"] == 50


def test_cli_measure_tiny(capsys):
    assert main(["measure", "--iterations", "10", "--repeats", "1"]) == 0
    assert "per derivation" in capsys.readouterr().out


def test_cli_measure_json(capsys):
    assert main(["measure", "--iterations", "10", "--repeats", "1", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["repeats"] == 1


def test_cli_measure_scrypt(capsys):
    assert main(["measure", "--kind", "scrypt", "--memory", "16", "--repeats", "1"]) == 0
    assert "scrypt" in capsys.readouterr().out


def test_cli_measure_rejects_bad_scrypt(capsys):
    assert main(["measure", "--kind", "scrypt", "--memory", "3", "--repeats", "1"]) == 2
    assert "power of two" in capsys.readouterr().err


def test_cli_calibrate(capsys):
    assert main(["calibrate", "--target-ms", "2", "--repeats", "1"]) == 0
    assert "Calibrated to 2 ms" in capsys.readouterr().out


def test_cli_password(capsys):
    assert main(["password", "--charset", "94", "--length", "8"]) == 0
    assert "52.4 bits" in capsys.readouterr().out


def test_cli_password_rejects_bad_charset(capsys):
    assert main(["password", "--charset", "1", "--length", "8"]) == 2
    assert "error:" in capsys.readouterr().err


def test_cli_attackers(capsys):
    assert main(["attackers"]) == 0
    output = capsys.readouterr().out
    for name in ATTACKER_RATES:
        assert name in output


def test_cli_required_entropy(capsys):
    assert main(["required-entropy", "--iterations", "1000", "--that-many-years", "10"]) == 0
    output = capsys.readouterr().out
    assert "needed" in output
    assert "bits of password entropy" in output


@pytest.fixture
def tiny_profiles(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps(
            {
                "profiles": [
                    {"name": "tiny-pbkdf2", "kind": "pbkdf2-sha256", "iterations": 50},
                    {"name": "tiny-scrypt", "kind": "scrypt", "memory_kib": 16},
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


def test_cli_select_tiny(tiny_profiles, capsys):
    assert main(["select", "--profiles", str(tiny_profiles), "--repeats", "1"]) == 0
    output = capsys.readouterr().out
    assert "Cost of each profile" in output
    assert "Time to crack a 50-bit password" in output


def test_cli_select_json(tiny_profiles, capsys):
    argv = ["select", "--profiles", str(tiny_profiles), "--repeats", "1", "--format", "json"]
    assert main(argv) == 0
    assert len(json.loads(capsys.readouterr().out)) == 2


def test_cli_matrix(tiny_profiles, capsys):
    argv = ["matrix", "--profiles", str(tiny_profiles), "--repeats", "1", "--bits", "30,60"]
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert "30b" in output and "60b" in output
    assert "Time to crack one hash" in output


def test_cli_matrix_bad_bits(tiny_profiles, capsys):
    argv = ["matrix", "--profiles", str(tiny_profiles), "--bits", "abc"]
    assert main(argv) == 2
    assert "error:" in capsys.readouterr().err


def test_cli_select_missing_file(tmp_path, capsys):
    assert main(["select", "--profiles", str(tmp_path / "none.json")]) == 2
    assert "error:" in capsys.readouterr().err


def test_cli_select_empty_profiles(tmp_path, capsys):
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"profiles": []}), encoding="utf-8")
    assert main(["select", "--profiles", str(path)]) == 2
    assert "no profiles" in capsys.readouterr().err
