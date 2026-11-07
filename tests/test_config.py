import pytest 
from pydantic import ValidationError
from src.config import ENV_VAR, load_config
from src.stream_processor.windows import WindowProcessor

def write(tmp_path, text):
    p = tmp_path / "cfg.yaml"
    p.write_text(text)
    return str(p)

def test_default_config_loads():
    cfg = load_config()
    assert cfg.windows.sizes_s == [1, 10, 60]
    assert cfg.windows.lateness_s >= 0

def test_custom_path_and_sorting(tmp_path):
    cfg = load_config(write(tmp_path, "windows: {sizes_s: [60, 1, 10], lateness_s: 2}"))
    assert cfg.windows.sizes_s == [1, 10, 60]
    assert cfg.windows.lateness_s == 2

def test_env_var_overrides_default(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_VAR, write(tmp_path, "windows: {sizes_s: [1], lateness_s: 0}"))
    assert load_config().windows.sizes_s == [1]

@pytest.mark.parametrize("bad", [
    "windows: {sizes_s: [], lateness_s: 1}",
    "windows: {sizes_s: [1, 1], lateness_s: 1}",
    "windows: {sizes_s: [0, 10], lateness_s: 1}",
    "windows: {sizes_s: [1, 10], lateness_s: -1}",
    "windows: {sizes_s: [1, 10]}",
    "okna: {sizes_s: [1]}",
])

def test_invalid_config_is_rejected(tmp_path, bad):
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, bad))

def test_processor_from_config(tmp_path):
    cfg = load_config(write(tmp_path, "windows: {sizes_s: [1, 5], lateness_s: 3}"))
    p = WindowProcessor.from_config("src_ip", cfg.windows)
    assert p.window_sizes == (1, 5)
    assert p.lateness_s == 3