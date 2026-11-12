import pytest 
import yaml
from pydantic import ValidationError
from src.config import DEFAULT_PATH, ENV_VAR, load_config
from src.stream_processor.windows import WindowProcessor

def base():
    return yaml.safe_load(DEFAULT_PATH.read_text(encoding="utf-8"))

def write(tmp_path, data):
    p = tmp_path / "cfg.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(p)

def test_default_config_loads():
    cfg = load_config()
    assert cfg.windows.sizes_s == [1, 10, 60]
    assert cfg.windows.lateness_s >= 0
    assert cfg.alerts.severity.medium < cfg.alerts.severity.critical

def with_windows(**override):
    d = base()
    d["windows"].update(override)
    return d

def test_custom_path_and_sorting(tmp_path):
    cfg = load_config(write(tmp_path, with_windows(sizes_s=[60, 1, 10], lateness_s=2)))
    assert cfg.windows.sizes_s == [1, 10, 60]
    assert cfg.windows.lateness_s == 2

def test_env_var_overrides_default(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_VAR, write(tmp_path, with_windows(lateness_s=7)))
    assert load_config().windows.lateness_s == 7

@pytest.mark.parametrize("override", [
    {"sizes_s": []},                
    {"sizes_s": [1, 1, 10, 60]},   
    {"sizes_s": [0, 10, 60]},        
    {"lateness_s": -1},              
    {"dedup_ttl_s": 0},              
])
def test_invalid_windows_value_is_rejected(tmp_path, override):
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, with_windows(**override)))
 
 
@pytest.mark.parametrize("field", ["sizes_s", "lateness_s", "dedup_ttl_s"])
def test_missing_windows_field_is_rejected(tmp_path, field):
    d = base()
    del d["windows"][field]
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, d))
 
 
@pytest.mark.parametrize("section", ["windows", "detection", "alerts"])
def test_missing_section_is_rejected(tmp_path, section):
    d = base()
    del d[section]
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, d))
 
 
def test_threshold_for_unknown_window_is_rejected(tmp_path):
    d = base()
    d["detection"]["rules"]["port_scan"]["unique_dst_ports"][5] = 10   # okna 5 s nie ma w windows
    with pytest.raises(ValidationError, match="not in windows.sizes_s"):
        load_config(write(tmp_path, d))
 
 
def test_non_positive_threshold_is_rejected(tmp_path):
    d = base()
    d["detection"]["rules"]["dos_like"]["connections"][1] = 0
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, d))
 
 
def test_severity_bands_must_increase(tmp_path):
    d = base()
    d["alerts"]["severity"] = {"medium": 5, "high": 2, "critical": 10}
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, d))
 
 
def test_processor_from_config(tmp_path):
    cfg = load_config(write(tmp_path, with_windows(lateness_s=3, dedup_ttl_s=45)))
    p = WindowProcessor.from_config("src_ip", cfg.windows)
    assert p.window_sizes == (1, 10, 60)
    assert p.lateness_s == 3
    assert p.dedup_ttl_s == 45