"""wyznacza baseline (profil normalnego ruchu) i wpisuje do config/default.yaml
python -m scripts.build_baseline data/normal_1h.pcap - sam raport
python -m scripts.build_baseline data/normalna_godzina.pcap --update-config  - wpisujemy wartosc do default.yaml
python -m scripts.build_baseline a.pcap b.pcap --update-config  - jedna norma z kilku nagran 

hosty o innej normie (np. DNS) wypisujemy jako podpowiedz a do pliku trafiaja (blok groups) z opcja --with-groups
(lista zaufanych hostow konkretej sieci), jesli w podanym pliku zadziala jakas inna zasada, skrypt ostrzeha ze plik moze
byc zanieczyszczony - wypisuje z --exclude-ip podejrzany adres"""

import argparse
import logging
from collections import Counter
from pathlib import Path
import yaml
import json
from src.baseline import abnormal_section, build_baseline, quality_warnings
from src.config import DEFAULT_PATH, Config, load_config
from src.pipeline import run_flows
from src.stream_processor.windows import WindowProcessor


#------------------- podmiana tekstu w default.yaml

def _indent(line):
    return len(line) - len(line.lstrip(" "))

def _block_end(lines, start, indent):
    j = start + 1
    while j < len(lines) and (not lines[j].strip() or _indent(lines[j]) > indent):
        j += 1
    while j > start + 1 and not lines[j - 1].strip():
        j -= 1
    return j

def _find_key(lines, key, lo, hi, indent):
    for i in range(lo, hi):
        if _indent(lines[i]) == indent and lines[i].lstrip().startswith(key + ":"):
            return i
    raise ValueError(f"'{key}' not found in the abnormal section of configuration file")

def render_baseline(baseline: dict, source: str) -> list:
    width = max(len(f) for f in baseline) + 1
    out = [f"      baseline:                    #profil zrodla; wyliczono z: {source}"]
    for f, per_w in baseline.items():
        vals = ", ".join(f"{w}: {v:g}" for w, v in per_w.items())
        out.append(f"        {f + ':':<{width}} {{{vals}}}")
    return out

def render_groups(groups: dict) -> list:
    if not groups:
        return ["      groups: {}"]
    out = ["      groups:                   #hosty o innej normie (wyliczone przez scripts.build_baseline)"]
    for name, g in groups.items():
        hosts = ", ".join(f'"{h}"' for h in g["hosts"])
        out += [f"        {name}:", f"          hosts: [{hosts}]", f"          enabled: {str(g['enabled']).lower()}", f"          multiplier: {g['multiplier']:g}"]
    return out

def patch_abnormal_in_yaml(text: str, baseline: dict, source: str, groups=None) -> str:
    lines = text.splitlines()
    a = next((i for i, l in enumerate(lines) if l.startswith("    abnormal:")), None)
    if a is None:
        raise ValueError("'abnormal' section not found in the configuration file")
    b = _find_key(lines, "baseline", a+1, _block_end(lines, a, 4), 6)
    lines[b:_block_end(lines, b, 6)] = render_baseline(baseline, source)
    if groups is not None:
        g = _find_key(lines, "groups", a+1, _block_end(lines, a, 4), 6)
        lines[g:_block_end(lines, g, 6)] = render_groups(groups)
    return "\n".join(lines) + "\n"

def update_config_file(path: Path, section: dict, source: str, with_groups: bool) -> None:
    new_text = patch_abnormal_in_yaml(path.read_text(encoding="utf-8"), section["baseline"], source, section["groups"] if with_groups else None)
    Config.model_validate(yaml.safe_load(new_text))
    path.write_text(new_text, encoding="utf-8")

#---------------------- wczytywanie nagran

def load_flows(path: str) -> list:
    if path.lower().endswith((".pcap", ".pcapng", ".trace", ".cap")):
        from src.extractor import extract_flows
        flows = extract_flows(path)
    else:
        with open(path, encoding="utf-8") as f:
            flows = [json.loads(line) for line in f if line.strip()]
    if not flows:
        raise SystemExit(f"No flows found in {path}")
    flows.sort(key=lambda f: f["start_timestamp"])
    return flows

def select_flows(flows: list, exclude: set) -> list:
    if not exclude:
        return flows
    return [f for f in flows if f["src_ip"] not in exclude]

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", nargs="+", help="PCAP or JSONL with flows from normal, clean traffic (one or more)")
    ap.add_argument("--update-config", nargs="?", const=str(DEFAULT_PATH), metavar="PLIK", help="write baseline to the configuration file (default: config/default.yaml)")
    ap.add_argument("--with-groups", action="store_true", help="include groups in the configuration file (addresses of hosts with higher norm e.g. DNS)")
    ap.add_argument("--exclude-ip", action="append", default=[], help="exclude a source (host) (can be used multiple times)")
    ap.add_argument("--statistic", choices=["p95", "p99", "max"], default="p99", help="what we take as the host's norm (default: p99)")
    ap.add_argument("--multiplier", type=float, help="deviation multiplier used for suggesting outlier groups (default: from config)")
    ap.add_argument("--min_samples", type=int, default=500)
    ap.add_argument("--min-host-samples", type=int, default=100, help="how many samples the host must have to be counted in the baseline")
    ap.add_argument("--typical-quantile", type=float, default=0.9, help="typical source baseline: quantile across hosts (default: 0.9)")
    args = ap.parse_args(argv)
    if args.with_groups and not args.update_config:
        ap.error("--with-groups can be used only with --update-config")

    cfg = load_config(args.update_config) if args.update_config else load_config()
    rule = cfg.detection.rules.abnormal
    features, windows = list(rule.baseline), rule.windows
    multiplier = args.multiplier or rule.multiplier

    all_windows, all_chosen, total_flows = [], [], 0
    for path in args.input:
        flows = load_flows(path)
        chosen = select_flows(flows, set(args.exclude_ip))
        if not chosen:
            raise SystemExit(f"No flows in {path} (check --exclude-ip).")
        span = chosen[-1]["start_timestamp"] - chosen[0]["start_timestamp"]
        print(f"{path}: chosen {len(chosen):,} out of {len(flows):,} flows, span: {span / 60:.1f} min")
        proc = WindowProcessor.from_config("src_ip", cfg.windows)
        for f in chosen:
            all_windows.extend(proc.add(f))
        all_windows.extend(proc.flush())
        all_chosen.append(chosen)
        total_flows += len(chosen)

    source = ", ".join(Path(p).name for p in args.input)
    baseline = build_baseline(
        all_windows, features=features, window_sizes=windows, min_host_samples=args.min_host_samples, 
        typical_host_quantile=args.typical_quantile, meta={"source": source, "flows": total_flows}
    )
    section = abnormal_section(baseline, features, windows, multiplier, rule.min_values, args.statistic)
    m = baseline.meta
    print(f"\nHosts in baseline period: {m['hosts_total']}, with enough samples (>= {m['min_host_samples']}): {m['hosts_with_profile']}")
    print(f"\nTYPICAL SOURCE PROFILE (baseline = {args.statistic} per host, {args.typical_quantile:.0%} quantile)")
    print(f"\n{'feature':<18}{'win':>5}{'samples':>9}{'hosts':>8}{'baseline':>9}{'alert thresh':>14}")
    for f, per_w in section["baseline"].items():
        for w, norm in per_w.items():
            s = baseline.stats[f][w]
            thr = max(norm * rule.multiplier, rule.min_values.get(f, 0.0))
            print(f"{f:<18}{w:>4}s{s.n:>9,}{s.n_keys:>8}{norm:>9.2f}{'> ' + format(thr, '.1f'):>14}")

    if section["groups"]:
        print("\nHOSTS WITH DIFFERENT BASELINE: in normal traffic they exceed typical host thresholds so they would get fake alerts "
              "\n If its know infrastructure (e.g. DNS) add them to abnormal.groups (or use --with-groups):")
        for name, g in section["groups"].items():
            what = "rule disabled" if not g["enabled"] else f"multiplier x{g['multiplier']:g}"
            print(f"  {name}: {what}, hosts: {len(g['hosts'])}: {', '.join(g['hosts'][:6])}"
                  f"{' ...' if len(g['hosts']) > 6 else ''}")
    else:
        print("\nOutlier hosts: none (no hosts exceed the typical source threshold)")
    print()
    for w in quality_warnings(baseline, args.min_samples):
        print("WARNING: ", w)

    suspects = Counter()
    for chosen in all_chosen:
        for d in run_flows(chosen, cfg):
            if "rule" in d.method.split("+") and d.type != "ABNORMAL_CONN_PATTERN" and d.source:
                suspects[(d.type, d.source)] += 1
    if suspects:
        print("\nWARNING: rules detected suspicious sources during the baseline period (baseline might be contaminated)")
        for (t, src), n in suspects.most_common(10):
            print(f"   {src:<18}{t}  (--exclude-ip {src})")
    else:
        print("Cleanliness check: no rules triggered during the baseline period")
    if args.update_config:
        update_config_file(Path(args.update_config), section, source, args.with_groups)
        print(f"\nUpdated {args.update_config}: abnormal.baseline"
              f"{' and abnormal.groups' if args.with_groups else ''} section. Review changes: git diff {args.update_config}")
    else:
        print("\n(Add --update-config to write the calculated baseline to config/default.yaml)")
    return section

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()


