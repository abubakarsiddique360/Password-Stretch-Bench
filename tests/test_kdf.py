import pytest

from password_stretch_bench.kdf import (
    DEFAULT_PASSWORD,
    KdfError,
    Params,
    calibrate,
    derive,
    measure,
)


class FakeClock:
    """Deterministic timer: returns the next queued timestamp on every call."""

    def __init__(self, stamps):
        self.stamps = list(stamps)

    def __call__(self) -> float:
        if not self.stamps:
            return 1000.0
        return self.stamps.pop(0)


def test_pbkdf2_is_deterministic_and_long():
    params = Params("pbkdf2-sha256", iterations=10)
    first = derive(params)
    assert first == derive(params)
    assert len(first) == 32


def test_different_passwords_differ():
    params = Params("pbkdf2-sha256", iterations=10)
    assert derive(params, password=b"a") != derive(params, password=b"b")


def test_scrypt_matches_reference_length():
    params = Params("scrypt", memory_kib=16, parallelism=1)
    assert len(derive(params)) == 32


def test_pbkdf2_rejects_zero_iterations():
    with pytest.raises(KdfError, match="at least one iteration"):
        derive(Params("pbkdf2-sha256", iterations=0))


def test_scrypt_rejects_non_power_of_two():
    with pytest.raises(KdfError, match="power of two"):
        derive(Params("scrypt", memory_kib=3))


def test_unknown_kind():
    with pytest.raises(KdfError, match="unsupported kdf"):
        derive(Params("bcrypt"))


def test_label_formats():
    assert Params("pbkdf2-sha256", iterations=600000).label == "pbkdf2-sha256 600,000"
    assert Params("scrypt", memory_kib=32768).label == "scrypt n=2^15 r=8 p=1"


def test_measure_takes_the_best_of_the_runs():
    clock = FakeClock([0.0, 0.5, 10.0, 10.2])
    params = Params("pbkdf2-sha256", iterations=1)
    measurement = measure(params, repeats=2, batch=2, timer=clock)
    # first run: 0.5 / 2 = 0.25 s per derivation; second: 0.2 / 2 = 0.1 s - the best wins
    assert measurement.seconds == pytest.approx(0.1)
    assert measurement.per_second == pytest.approx(10.0)
    assert measurement.repeats == 2
    assert measurement.batch == 2


def test_measure_batch_divides_the_elapsed_time():
    clock = FakeClock([0.0, 1.0])
    measurement = measure(Params("pbkdf2-sha256", iterations=1), repeats=1, batch=4, timer=clock)
    assert measurement.seconds == pytest.approx(0.25)


def test_measurement_serialises():
    clock = FakeClock([0.0, 0.002])
    payload = measure(
        Params("pbkdf2-sha256", iterations=1), repeats=1, batch=1, timer=clock
    ).as_dict()
    assert payload["kind"] == "pbkdf2-sha256"
    assert payload["per_derivation_ms"] == pytest.approx(2.0)


def test_calibrate_rejects_non_positive_target():
    with pytest.raises(KdfError, match="target must be positive"):
        calibrate("pbkdf2-sha256", 0)


def test_calibrate_scrypt_returns_a_power_of_two():
    measurement = calibrate("scrypt", 0.001, repeats=1)
    assert measurement.params.kind == "scrypt"
    assert measurement.params.memory_kib & (measurement.params.memory_kib - 1) == 0


def test_calibrate_pbkdf2_lands_near_the_target():
    measurement = calibrate("pbkdf2-sha256", 0.01, repeats=1)
    assert measurement.params.kind == "pbkdf2-sha256"
    assert measurement.params.iterations > 1000
    assert 0.0005 < measurement.per_derivation < 0.2


def test_measure_default_password_is_a_phrase():
    assert len(DEFAULT_PASSWORD) > 20
