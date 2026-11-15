import os
import ipaddress
from pathlib import Path
from typing import Optional, Annotated, Literal
import yaml
from pydantic import BaseModel, Field, field_validator, PositiveFloat, model_validator, NonNegativeFloat

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PATH = PROJECT_ROOT / "config" / "default.yaml"
ENV_VAR = "NETGUARD_CONFIG"

Port = Annotated[int, Field(ge=0, le=65535)]
PerWindow = dict[int, PositiveFloat]
SrcFeature = Literal["connections", "packets_per_s", "bytes_per_s", "unique_dst_ports", "unique_dst_addrs", "new_conn_rate"]

class WindowsConfig(BaseModel):
    sizes_s: list[int] = Field(min_length=1)
    lateness_s: float = Field(ge=0)
    dedup_ttl_s: PositiveFloat

    @field_validator("sizes_s")
    @classmethod
    def sizes_posistive_unique(cls, v):
        if any(s <= 0 for s in v):
            raise ValueError("window sizes must be positive")
        if len(set(v)) != len(v):
            raise ValueError("window sizes must be unique")
        return sorted(v)

class PortScanRule(BaseModel):
    unique_dst_ports: PerWindow
    min_ports_per_host: float = Field(ge=1.0)
    ignore_broadcast: bool

class DosLikeRule(BaseModel):
    connections: PerWindow
    packets_per_s: PerWindow = Field(default_factory=dict)

class BruteForceRule(BaseModel):
    attempts: PerWindow
    ports: list[Port] = Field(min_length=1)

class AbnormalGroup(BaseModel):
    hosts: list[str] = Field(min_length=1)
    enabled: bool
    multiplier: float = Field(ge=1)

    @field_validator("hosts")
    @classmethod
    def valid_hosts(cls, v):
        for h in v:
            try:
                ipaddress.ip_network(h, strict=False)
            except ValueError as e:
                raise ValueError(f"'{h}' is not an IP address or CIDR network")
        return v

class AbnormalRule(BaseModel):
    windows: list[int] = Field(min_length=1)
    multiplier: float = Field(ge=1)
    baseline: dict[SrcFeature, dict[int, NonNegativeFloat]] = Field(min_length=1)
    min_values: dict[SrcFeature, NonNegativeFloat]
    groups: dict[str, AbnormalGroup]

class RuleThresholds(BaseModel):
    port_scan: PortScanRule
    dos_like: DosLikeRule
    brute_force: BruteForceRule
    abnormal: AbnormalRule

class MLConfig(BaseModel):
    windows: list[int] = Field(min_length=1)
    z_score_threshold: PositiveFloat
    alpha: float = Field(gt=0, le=1)
    min_samples: int = Field(ge=2)
    min_sigma: PositiveFloat
    ttl_s: PositiveFloat

class DetectionConfig(BaseModel):
    rules: RuleThresholds 
    ml: MLConfig

class SeverityBands(BaseModel):
    medium: float
    high: float
    critical: float

    @model_validator(mode="after")
    def increasing(self):
        if not (1.0 < self.medium < self.high < self.critical):
            raise ValueError("severity bands must satisfy 1 < medium < high < critical")
        return self

class AlertConfig(BaseModel):
    cooldown_s: float = Field(ge=0)
    severity: SeverityBands

class Config(BaseModel):
    windows: WindowsConfig
    detection: DetectionConfig
    alerts: AlertConfig

    @model_validator(mode="after")
    def referenced_windows_exist(self):
        sizes = set(self.windows.sizes_s)
        r = self.detection.rules
        tables = {
            "rules.port_scan": r.port_scan.unique_dst_ports,
            "rules.dos_like": r.dos_like.connections,
            "rules.dos_like.packets_per_s": r.dos_like.packets_per_s,
            "rules.brute_force": r.brute_force.attempts,
            "rules.abnormal.windows": dict.fromkeys(r.abnormal.windows, 1),
            **{f"rules.abnormal.baseline.{f}": per_w for f, per_w in r.abnormal.baseline.items()},
            "ml.windows": dict.fromkeys(self.detection.ml.windows, 1),
        }
        for name, table in tables.items():
            unknown = set(table) - sizes
            if unknown:
                raise ValueError(f"{name} uses window sizes {sorted(unknown)} that are not in windows.sizes_s")
        return self

def load_config(path: Optional[str] = None) -> Config:
    chosen = Path(path or os.environ.get(ENV_VAR) or DEFAULT_PATH)
    with open(chosen, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return Config.model_validate(raw)