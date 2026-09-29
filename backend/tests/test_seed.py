"""Seeding a fresh data directory from a pre-built bundle (hosts with an ephemeral disk)."""
from backend import bootstrap


def test_seed_copies_missing_files_only(tmp_path, monkeypatch):
    seed = tmp_path / "seed"
    (seed / "models").mkdir(parents=True)
    (seed / "samples").mkdir()
    (seed / "models" / "m.joblib").write_bytes(b"model")
    (seed / "samples" / "a.pcap").write_bytes(b"new")
    model_dir, sample_dir = tmp_path / "data" / "models", tmp_path / "data" / "samples"
    model_dir.mkdir(parents=True)
    sample_dir.mkdir()
    (sample_dir / "a.pcap").write_bytes(b"existing")
    monkeypatch.setattr(bootstrap, "SAMPLE_DIR", sample_dir)
    monkeypatch.setattr("backend.config.MODEL_DIR", model_dir)
    monkeypatch.setenv("SECURIQ_SEED_DIR", str(seed))

    assert bootstrap.seed_from_bundle() is True
    assert (model_dir / "m.joblib").read_bytes() == b"model"
    assert (sample_dir / "a.pcap").read_bytes() == b"existing"  # never overwritten
    assert bootstrap.seed_from_bundle() is False               # nothing left to copy


def test_seed_is_off_without_env(monkeypatch):
    monkeypatch.delenv("SECURIQ_SEED_DIR", raising=False)
    assert bootstrap.seed_from_bundle() is False
