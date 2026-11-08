import json
import logging
import sys
import time

from src.config import load_config
from src.stream_processor.windows import WindowProcessor

def main(in_path, out_path=None):
    cfg = load_config()
    src_proc = WindowProcessor.from_config("src_ip", cfg.windows)
    dst_proc = WindowProcessor.from_config("dst_ip", cfg.windows)
    out = open(out_path, "w", encoding="utf-8") if out_path else None

    best_ports = {}
    best_conns = {}
    n_flows = n_windows = 0
    t0 = time.perf_counter()

    def handle(results):
        nonlocal n_windows
        for r in results:
            n_windows += 1
            if out:
                out.write(r.model_dump_json() + "\n")
            if r.window_size_s == 10:
                if r.key_type == "src_ip":
                    v = r.features["unique_dst_ports"]
                    if v > best_ports.get(r.key, (0, 0))[0]:
                        best_ports[r.key] = (v, r.window_end)
                else:
                    v = r.features["connections"]
                    if v > best_conns.get(r.key, (0, 0))[0]:
                        best_conns[r.key] = (v, r.window_end)

    with open(in_path, encoding="utf-8-sig") as f:
        for line in f:
            flow = json.loads(line)
            n_flows += 1
            handle(src_proc.add(flow))
            handle(dst_proc.add(flow))
    handle(src_proc.flush())
    handle(dst_proc.flush())
    if out:
        out.close()

    dt = time.perf_counter() - t0
    print(f"flows: {n_flows}, windows emitted: {n_windows}, "
          f"late dropped: {src_proc.late}, time: {dt:.1f}s ({n_flows / dt:,.0f} flows/s, 2 profiles)")
    print("\nTop 5 sources by unique destination ports in a 10 s window:")
    for k, (v, _) in sorted(best_ports.items(), key=lambda kv: -kv[1][0])[:5]:
        print(f" {k:<18} {v:>8.0f}")
    print("\nTop 5 targets by connections in a 10 s window:")
    for k, (v, _) in sorted(best_conns.items(), key=lambda kv: -kv[1][0])[:5]:
        print(f" {k:<18} {v:>8.0f}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) not in (2,3):
        sys.exit("usage: python -m scripts.windows_demo <flows.jsonl> [features.jsonl]")
    main(*sys.argv[1:])