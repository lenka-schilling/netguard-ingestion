from src.config import SeverityBands
from src.messages import DetectionType, Method, RawDetection, Severity

def severity_from_ratio(ratio: float, bands: SeverityBands) -> Severity:
    if ratio >= bands.critical:
        return Severity.CRITICAL
    if ratio >= bands.high:
        return Severity.HIGH
    if ratio >=bands.medium:
        return Severity.MEDIUM
    return Severity.LOW

def confidence_from_ratio(ratio: float, both_methods: bool = False) -> float:
    """0,5to nad progiem, pod 1 podchodzi przy duzych przekroczeniach
    zgodnosc rules i ml podnosi pewnosc o 0,1"""
    r = max(ratio, 1.0)
    conf = 0.5 + 0.5 * (1 - 1 / r)
    if both_methods:
        conf += 0.1
    return round(min(conf, 1.0), 3)

def explain(raw: RawDetection) -> str:
    """tekst dla operatora czyli co zaobserwowano jaki prog i w jakim oknie"""
    w = raw.window_size_s
    feature, val = next(iter(raw.observed.items()))
    thr = raw.treshold[feature]

    if raw.method == Method.ZSCORE:
        c = raw.context
        return(f"{c['feature']} for {raw.key} reached {val:g} within {w} s, far from its rolling"
               f"baseline (mean {c['mean']:.1f}, std {c['std']:.1f}): z = {c['z_score']:.1f} threshold {thr:g}.")
    t = raw.type
    if t == DetectionType.PORT_SCAN:
        target = f" on {raw.destination}" if raw.destination else ""
        return (f"Source {raw.key} contacted {val:g} distinct destiantion ports{target} within {w} s (threshold {thr:g}).")
    if t == DetectionType.BRUTE_FORCE:
        return (f"Source {raw.key} made {val:g} connection attempts to {raw.destination}:"
                f"{raw.context.get('port')} within {w} s (threshold {thr:g}).")
    if t == DetectionType.DOS_LIKE:
        n = raw.context.get("unique_src_addrs")
        srcs = f" from {n:g} distinct sources" if n else ""
        return (f"Target {raw.key} received {val:g} connections{srcs} within {w} s (threshold {thr:g}).")
    return (f"Source {raw.key} contacted {val:g} distinct destination addresses within {w} s (threshold {thr:g}).")