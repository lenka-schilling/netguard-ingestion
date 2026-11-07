import ipaddress
import json
import os
import tempfile
import unittest
from collections import Counter
from statistics import median

from src.models import Flow
from src.simulator.scenarios import CLIENTS
from src.simulator.simulator import WARMUP, TrafficSimulator, main

START = 1_700_000_000.0
ALL_SCENARIOS = ["port_scan", "dos", "brute_force", "abnormal_pattern"]


def simulate(scenarios=(), **kwargs):
    kwargs.setdefault("seed", 7)
    kwargs.setdefault("rate", 100)
    kwargs.setdefault("duration", 30)
    simulator = TrafficSimulator(scenarios=scenarios, start_time=START, **kwargs)
    return simulator, list(simulator.flows())


def content(sim_flow):
    """Pola przepływu bez flow_id i ingested_at, bo te są losowe/zależne od czasu i nie da się ich porównać."""
    data = sim_flow.flow.to_dict()
    del data["flow_id"], data["ingested_at"]
    return data


class TestTrafficSimulator(unittest.TestCase):

    # 1. Ruch normalny: liczba przepływów, kolejność i zakres czasu
    def test_normal_traffic_rate_and_ordering(self):
        """Sprawdza, czy ruch normalny ma zadaną intensywność, rosnące znaczniki czasu i etykietę normal."""
        simulator, flows = simulate(rate=200, duration=20)

        self.assertAlmostEqual(len(flows), 200 * 20, delta=200 * 20 * 0.1)
        timestamps = [f.flow.start_timestamp for f in flows]
        self.assertEqual(timestamps, sorted(timestamps))
        self.assertGreaterEqual(timestamps[0], START)
        self.assertLess(timestamps[-1], simulator.end_time)
        self.assertTrue(all(f.label == "normal" and f.episode_id is None for f in flows))

    # 2. Symulator ma zwracać ten sam model Flow, co ekstrakcja z PCAP
    def test_flows_use_flow_model(self):
        """Sprawdza, czy każdy przepływ jest obiektem Flow z poprawnymi portami i licznikami."""
        _, flows = simulate(scenarios=ALL_SCENARIOS, anomaly_scale=0.2)

        for sim_flow in flows:
            data = sim_flow.flow.to_dict()
            self.assertIsInstance(sim_flow.flow, Flow)
            self.assertIn(data["protocol"], ("TCP", "UDP"))
            self.assertTrue(0 <= data["src_port"] <= 65535 and 0 <= data["dst_port"] <= 65535)
            self.assertGreaterEqual(data["packet_count"], 1)
            self.assertGreater(data["byte_count"], 0)
            self.assertGreaterEqual(data["duration"], 0)

    # 3. Bezpieczeństwo (NFR09): symulator może używać tylko adresów prywatnych/dokumentacyjnych
    def test_only_laboratory_addresses_are_used(self):
        """Sprawdza, czy symulator nie generuje żadnego publicznego (routowalnego) adresu IP."""
        _, flows = simulate(scenarios=ALL_SCENARIOS, anomaly_scale=0.2)

        addresses = {f.flow.src_ip for f in flows} | {f.flow.dst_ip for f in flows}
        self.assertTrue(all(ipaddress.ip_address(a).is_private for a in addresses))

    # 4. Port Scan: jedno źródło, wiele różnych portów jednego celu
    def test_port_scan_signature(self):
        """Sprawdza charakterystykę skanowania portów i zgodność z ground truth."""
        simulator, flows = simulate(scenarios=["port_scan"])
        episode = simulator.ground_truth()["episodes"][0]
        scan = [f.flow for f in flows if f.label == "port_scan"]

        self.assertEqual(episode["flow_count"], len(scan))
        self.assertEqual({f.src_ip for f in scan}, set(episode["src_ips"]))
        self.assertEqual({f.dst_ip for f in scan}, set(episode["dst_ips"]))
        ports = [f.dst_port for f in scan]
        self.assertEqual(len(ports), len(set(ports)), "Każdy port powinien być sprawdzony raz")
        self.assertGreater(len(ports), 500)

    # 5. DoS-like: wiele źródeł, jeden cel, bardzo wysoka intensywność
    def test_dos_signature(self):
        """Sprawdza, czy flood kieruje do jednego celu znacznie więcej połączeń niż ruch normalny."""
        simulator, flows = simulate(scenarios=["dos"])
        episode = simulator.ground_truth()["episodes"][0]
        dos = [f.flow for f in flows if f.label == "dos"]

        self.assertEqual({f.dst_ip for f in dos}, set(episode["dst_ips"]))
        self.assertGreater(len({f.src_ip for f in dos}), 100)
        self.assertGreater(len(dos) / (episode["end"] - episode["start"]), 10 * simulator.rate)

    # 6. Brute Force-like: powtarzane połączenia do tej samej usługi
    def test_brute_force_signature(self):
        """Sprawdza, czy brute force to wiele połączeń z jednego źródła na ten sam cel i port."""
        _, flows = simulate(scenarios=["brute_force"], duration=120)
        brute = [f.flow for f in flows if f.label == "brute_force"]
        normal_per_service = Counter((f.flow.src_ip, f.flow.dst_ip, f.flow.dst_port)
                                     for f in flows if f.label == "normal" and f.flow.dst_port == 22)

        self.assertEqual(len({(f.src_ip, f.dst_ip, f.dst_port) for f in brute}), 1)
        self.assertGreater(len(brute), 300)
        # W ruchu normalnym żaden klient nie łączy się z SSH nawet w przybliżeniu tak często jak atakujący
        self.assertGreater(len(brute), 20 * max(normal_per_service.values()))

    # 7. Abnormal Connection Pattern: odchylenie od profilu normalnego klienta
    def test_abnormal_pattern_deviates_from_baseline(self):
        """Sprawdza, czy zwykły klient nagle wysyła więcej, większych i dłuższych przepływów do nowego celu."""
        simulator, flows = simulate(scenarios=["abnormal_pattern"], duration=200)
        episode = simulator.ground_truth()["episodes"][0]
        victim = episode["src_ips"][0]
        self.assertIn(victim, CLIENTS)

        baseline = [f.flow for f in flows if f.label == "normal" and f.flow.src_ip == victim
                    and f.flow.start_timestamp < episode["start"]]
        abnormal = [f.flow for f in flows if f.label == "abnormal_pattern"]
        self.assertGreater(len(baseline), 0, "Klient powinien mieć ruch normalny jako baseline")

        baseline_seconds = episode["start"] - START
        episode_seconds = episode["end"] - episode["start"]
        self.assertGreater(len(abnormal) / episode_seconds, 2 * len(baseline) / baseline_seconds)
        self.assertGreater(sum(f.byte_count for f in abnormal) / episode_seconds,
                           10 * sum(f.byte_count for f in baseline) / baseline_seconds)
        self.assertGreater(median(f.to_dict()["duration"] for f in abnormal),
                           5 * median(f.to_dict()["duration"] for f in baseline))
        normal_destinations = {f.flow.dst_ip for f in flows if f.label == "normal"}
        self.assertNotIn(episode["dst_ips"][0], normal_destinations)

    # 8. Harmonogram: najpierw baseline, potem scenariusze po kolei i bez nakładania się
    def test_scenarios_are_scheduled_after_warmup_without_overlap(self):
        """Sprawdza, czy scenariusze startują po okresie baseline i nie nakładają się na siebie."""
        simulator, flows = simulate(scenarios=ALL_SCENARIOS, anomaly_scale=0.1)
        episodes = simulator.ground_truth()["episodes"]

        self.assertGreaterEqual(episodes[0]["start"], START + WARMUP)
        for previous, current in zip(episodes, episodes[1:]):
            self.assertGreaterEqual(current["start"], previous["end"])
        self.assertGreaterEqual(simulator.end_time, episodes[-1]["end"])

        for episode in episodes:
            timestamps = [f.flow.start_timestamp for f in flows if f.episode_id == episode["episode_id"]]
            self.assertEqual(len(timestamps), episode["flow_count"])
            self.assertTrue(all(episode["start"] <= t < episode["end"] for t in timestamps))

    # 9. Konfigurowalne obciążenie (wymóg z tygodnia 4): rate i anomaly_scale
    def test_load_is_configurable(self):
        """Sprawdza, czy rate skaluje ruch normalny, a anomaly_scale ruch scenariusza."""
        _, base = simulate(scenarios=["dos"])
        _, scaled = simulate(scenarios=["dos"], rate=300, anomaly_scale=2.0)

        for label, expected in (("normal", 3.0), ("dos", 2.0)):
            ratio = sum(f.label == label for f in scaled) / sum(f.label == label for f in base)
            self.assertAlmostEqual(ratio, expected, delta=expected * 0.1)

    # 10. Powtarzalność: z tym samym seedem ma wyjść dokładnie ten sam ruch
    def test_same_seed_is_reproducible(self):
        """Sprawdza, czy ten sam seed generuje identyczne przepływy, a inny seed - inne."""
        _, first = simulate(scenarios=["port_scan"], seed=123)
        _, second = simulate(scenarios=["port_scan"], seed=123)
        _, other = simulate(scenarios=["port_scan"], seed=124)

        self.assertEqual([content(f) for f in first], [content(f) for f in second])
        self.assertNotEqual([content(f) for f in first], [content(f) for f in other])

    # 11. Walidacja parametrów wejściowych
    def test_invalid_parameters_are_rejected(self):
        """Sprawdza, czy nieznany scenariusz lub niepoprawne obciążenie powoduje ValueError."""
        for kwargs in ({"scenarios": ["ddos"]}, {"rate": 0}, {"duration": -5}, {"anomaly_scale": 0}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    TrafficSimulator(**kwargs)

    # 12. Uruchomienie z konsoli: zapis przepływów i ground truth do plików
    def test_cli_writes_flows_and_ground_truth(self):
        """Sprawdza, czy uruchomienie z linii poleceń tworzy spójne pliki wyjściowe."""
        with tempfile.TemporaryDirectory() as tmp:
            flows_path = os.path.join(tmp, "flows.jsonl")
            truth_path = os.path.join(tmp, "truth.json")
            main(["--scenario", "brute_force", "--rate", "20", "--seed", "5",
                  "--output", flows_path, "--ground-truth", truth_path])

            with open(flows_path, encoding="utf-8") as f:
                flows = [json.loads(line) for line in f]
            with open(truth_path, encoding="utf-8") as f:
                truth = json.load(f)

        self.assertEqual(sum(truth["flow_counts"].values()), len(flows))
        self.assertEqual(truth["episodes"][0]["scenario"], "brute_force")
        self.assertEqual(truth["flow_counts"]["brute_force"], truth["episodes"][0]["flow_count"])
        self.assertEqual(set(flows[0]), set(Flow("10.0.0.1", "10.0.0.2", 1, 2, "TCP", 0.0).to_dict()))


if __name__ == "__main__":
    unittest.main()
