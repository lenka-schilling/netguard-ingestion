import logging
import math
import statistics
from typing import Iterable, Optional
from pydantic import BaseModel, Field
from src.messages import WindowFeatures

logger = logging.getLogger("NetGuard.Baseline")

STAT_FIELDS = ("mean", "std", "p50", "p95", "p99", "max")
MIN_HOSTS_FOR_TYPICAL = 3
MAX_GROUP_MULTIPLIER = 1000

def quantile(sorted_values: list, q: float) -> float:
    if not sorted_values:
        raise ValueError("empty sample")
    pos = q * (len(sorted_values) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)

class FeatureStats(BaseModel):
    n: int
    n_keys: int
    mean: float
    std: float
    p50: float
    p95: float
    p99: float
    max: float

def _stats(xs: list, n_keys: int) -> FeatureStats:
    xs = sorted(xs)
    return FeatureStats(n=len(xs), n_keys=n_keys, mean=statistics.fmean(xs), std=statistics.pstdev(xs), p50=quantile(xs, 0.50), p95=quantile(xs, 0.95), p99=quantile(xs, 0.99), max=xs[-1])

class Baseline(BaseModel):
    key_type: str = "src_ip"
    meta: dict = Field(default_factory=dict)
    stats: dict[str, dict[int, FeatureStats]]
    hosts: dict[str, dict[str, dict[int, FeatureStats]]] = Field(default_factory=dict)

def build_baseline(windows: Iterable[WindowFeatures], features: list, window_sizes: list, key_type: str = "src_ip", meta: Optional[dict] = None,
                   min_host_samples: int = 100, typical_host_quantile: float = 0.9) -> Baseline:
    samples = {}
    for win in windows:
        if win.key_type != key_type or win.window_size_s not in window_sizes:
            continue
        for f in features:
            v = win.features.get(f)
            if v is not None:
                samples.setdefault((f, win.window_size_s), {}).setdefault(win.key, []).append(float(v))

    stats, hosts, all_hosts, pooled_fallback = {}, {}, set(), []
    for (f, w), per_host in samples.items():
        all_hosts |= set(per_host)
        own = {h: _stats(xs, 1) for h, xs in per_host.items() if len(xs) >= min_host_samples}
        for h, st in own.items():
            hosts.setdefault(h, {}).setdefault(f, {})[w] = st
        if len(own) >= MIN_HOSTS_FOR_TYPICAL:
            typical = {fld: quantile(sorted(getattr(st, fld) for st in own.values()), typical_host_quantile) for fld in STAT_FIELDS}
            stats.setdefault(f, {})[w] = FeatureStats(n=sum(st.n for st in own.values()), n_keys=len(own), **typical)
        else: 
            pooled = [x for xs in per_host.values() for x in xs]
            stats.setdefault(f, {})[w] = _stats(pooled, len(per_host))
            pooled_fallback.append(f"{f}/{w}s")

    info = dict(meta or {})
    info.update({"hosts_total": len(all_hosts), "hosts_with_profile": len(hosts), "min_host_samples": min_host_samples, "typical_host_quantile": typical_host_quantile, "typical_from_pooled_samples": sorted(pooled_fallback)})
    return Baseline(key_type=key_type, meta=info, stats=stats, hosts=hosts)

def quality_warnings(baseline: Baseline, min_samples: int = 500, min_keys: int = 10) -> list:
    if not baseline.stats:
        return ["baseline is empty: no windows in the chosen period"]
    out = []
    pooled = baseline.meta.get("typical_from_pooled_samples") or []
    if pooled:
        out.append(f"fewer than {MIN_HOSTS_FOR_TYPICAL} hosts have their own profile ({', '.join(pooled)}): baseline of typical source is calculated from all pooled samples so the most active hosts dominate")
    for f, per_w in sorted(baseline.stats.items()):
        for w, s in sorted(per_w.items()):
            if s.n < min_samples:
                out.append(f"{f}, window {w} s: only {s.n} samples (need >= {min_samples} for a stable p99)")
            if s.n_keys < min_keys:
                out.append(f"{f}, window {w} s: typical source baseline from {s.n_keys} hosts (< {min_keys}), may describe individual hosts rather than the network")
            if s.p99 == 0:
                out.append(f"{f}, window {w} s: p99 = 0 (feature is almost always zero, relying on min_values)")
    return out

def typical_profile(baseline: Baseline, features: list, windows: list, statistic: str = "p99") -> dict:
    out = {}
    for f in features:
        for w in windows:
            s = baseline.stats.get(f, {}).get(w)
            if s is not None:
                out.setdefault(f, {})[w] = round(getattr(s, statistic), 3)
    return out

def suggest_groups(baseline: Baseline, features: list, windows: list, multiplier: float, min_values: dict, statistic: str = "p99") -> dict:
    needed = {}
    for host, per in baseline.hosts.items():
        need, over = 0.0, False
        for f in features:
            for w in windows:
                own = per.get(f, {}).get(w)
                typ = baseline.stats.get(f, {}).get(w)
                if own is None or typ is None:
                    continue
                own_norm, typ_norm = getattr(own, statistic), getattr(typ, statistic)
                if own_norm > max(typ_norm * multiplier, min_values.get(f, 0.0)):
                    over = True
                    need = max(need, own_norm * multiplier / typ_norm if typ_norm > 0 else math.inf)
        if over:
            needed[host] = need
    groups = {}
    for host, need in sorted(needed.items()):
        if need == math.inf or need > MAX_GROUP_MULTIPLIER:
            g = groups.setdefault("excluded", {"hosts": [], "enabled": False, "multiplier": multiplier})
        else:
            level = multiplier * 2 ** max(1, math.ceil(math.log2(max(need, multiplier) / multiplier)))
            g = groups.setdefault(f"high_volume_x{level:g}", {"hosts": [], "enabled": True, "multiplier": float(level)})
        g["hosts"].append(host)
    return groups

def abnormal_section(baseline: Baseline, features: list, windows: list, multiplier: float, min_values: dict, statistic: str = "p99", with_groups: bool = True) -> dict:
    profile = typical_profile(baseline, features, windows, statistic)
    return {
        "windows": list(windows),
        "multiplier": float(multiplier),
        "baseline": profile,
        "min_values": {f: v for f, v in min_values.items() if f in profile},
        "groups": suggest_groups(baseline, list(profile), windows, multiplier, min_values, statistic) if with_groups else {},

    }
