import itertools

from src.stream_processor.windows import WindowProcessor

_ids = itertools.count()

def mk(ts, src="10.0.0.5", dst="10.0.0.20", dport=80, **kw):
    d = dict(flow_id=f"f{next(_ids)}", ingested_at="2026-01-01T00:00:00", start_timestamp=ts, end_timestamp=ts,
            src_ip=src, dst_ip=dst, src_port=40000, dst_port=dport, protocol="TCP", packet_count=1, byte_count=60)
    d.update(kw)
    return d

def run(proc, flows):
    out = []
    for f in flows:
        out += proc.add(f)
    out += proc.flush()
    return out

def pick(results, key, w, end):
    found = [r for r in results if r.key == key and r.window_size_s == w and r.window_end == end]
    assert len(found) == 1, f"expected 1 result, got {len(found)}"
    return found[0]

def test_connections_in_one_second():
    res = run(WindowProcessor("src_ip"), [mk(1000.1), mk(1000.5), mk(1000.9)])
    r = pick(res, "10.0.0.5", 1, 1001.0)
    assert r.features["connections"] == 3
    assert r.features["packets_per_s"] == 3
    assert r.features["bytes_per_s"] == 180

def test_unique_ports_in_10s_window():
    flows = [mk(1000 + i // 4 + 0.1, dport=1 + i) for i in range(20)]
    res = run(WindowProcessor("src_ip"), flows)
    last10 = max((r for r in res if r.window_size_s == 10), key=lambda r: r.window_end)
    assert last10.features["unique_dst_ports"] == 20
    assert last10.features["connections"] == 20
    assert last10.features["unique_dst_addrs"] == 1
    r1 = pick(res, "10.0.0.5", 1, 1001.0)
    assert r1.features["unique_dst_ports"] == 4

def test_late_flow_is_dropped_and_counted():
    p = WindowProcessor("src_ip", lateness_s=5)
    p.add(mk(1000.0))
    p.add(mk(1010.0))
    assert p.add(mk(1001.0)) == []
    assert p.late == 1
    p.add(mk(1006.0))
    assert p.late == 1

def test_delayed_flow_within_lateness_goes_to_right_bucket():
    p = WindowProcessor("src_ip", lateness_s=5)
    res = run(p, [mk(1000.0), mk(1003.0), mk(1001.2)])
    r = pick(res, "10.0.0.5", 1, 1002.0)
    assert r.features["connections"] == 1
    assert p.late == 0

def test_expired_keys_are_removed():
    p = WindowProcessor("src_ip")
    p.add(mk(1000.0, src="10.0.0.5"))
    p.add(mk(1200.0, src="10.0.0.6"))
    assert "10.0.0.5" not in p.state

def test_destination_profile_counts_unique_sources():
    flows = [mk(1000.1, src=f"10.0.0.{i}", dst="10.0.0.20") for i in range(3)]
    res = run(WindowProcessor("dst_ip"), flows)
    r = pick(res, "10.0.0.20", 1, 1001.0)
    assert r.features["connections"] == 3
    assert r.features["unique_src_addrs"] == 3
    assert r.targets == []

def test_targets_for_brute_force():
    flows = [mk(1000 + i * 0.1, dport=22) for i in range(30)]
    res = run(WindowProcessor("src_ip"), flows)
    r = max((x for x in res if x.window_size_s == 10), key=lambda x: x.window_end)
    t = r.targets[0]
    assert t["dst_ip"] == "10.0.0.20"
    assert t["top_port"] == 22
    assert t["top_port_connections"] == 30
    assert t["unique_dst_ports"] == 1