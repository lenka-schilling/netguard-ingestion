import os
from pathlib import Path
from typing import Optional
import yaml
from pydantic import BaseModel, Field, field_validator

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config" / "default.yaml"
ENV_VAR = "NETGUARD_CONFIG"

class WindowsConfig(BaseModel):
    sizes_s: list[int] = Field(min_length=1)
    lateness_s: float = Field(ge=0)

    @field_validator("sizes_s")
    @classmethod
    def sizes_posistive_unique(cls, v):
        if any(s <= 0 for s in v):
            raise ValueError("window sizes must be positive")
        if len(set(v)) != len(v):
            raise ValueError("window sizes must be unique")
        return sorted(v)

class Config(BaseModel):
    windows: WindowsConfig

def load_config(path: Optional[str] = None) -> Config:
    chosen = Path(path or os.environ.get(ENV_VAR) or DEFAULT_PATH)
    with open(chosen, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return Config.model_validate(raw)