"""Symulator ruchu sieciowego NetGuard.

Generuje kontrolowany ruch normalny i cztery scenariusze anomalii z wymagań, a obciążenie
da się ustawić parametrami. Przy okazji zapisuje ground truth (kto, do kogo i kiedy robił
anomalię), żeby później dało się policzyć jakość detekcji.

jak korzystać:
    python -m src.simulator --scenario all --rate 500 --seed 42
"""
import argparse
import heapq
import json
import logging
import os
import random
import time
from collections import Counter, namedtuple

from src.simulator.scenarios import SCENARIO_DEFAULTS, SCENARIOS, normal_traffic

logger = logging.getLogger("NetGuard.Simulator")

# Ile sekund samego ruchu normalnego puszczamy na początku (baseline dla detekcji) i między scenariuszami
WARMUP = 60
GAP = 20

SimulatedFlow = namedtuple("SimulatedFlow", ["flow", "label", "episode_id"])


class TrafficSimulator:
    def __init__(self, scenarios=(), rate=200, duration=60.0, anomaly_scale=1.0, seed=None, start_time=None):
        unknown = [name for name in scenarios if name not in SCENARIOS]
        if unknown:
            raise ValueError(f"Unknown scenario(s): {', '.join(unknown)}. Available: {', '.join(SCENARIOS)}")
        if rate <= 0:
            raise ValueError("Normal traffic rate must be greater than 0 flows/s")
        if duration <= 0:
            raise ValueError("Duration must be greater than 0 s")
        if anomaly_scale <= 0:
            raise ValueError("Anomaly scale must be greater than 0")

        self.rate = rate
        self.anomaly_scale = anomaly_scale
        self.seed = seed
        self.start_time = start_time if start_time is not None else time.time()

        # Scenariusze idą po kolei, każdy dopiero po baseline i z przerwą na ruch normalny,
        # żeby się nie nakładały i żeby w ground truth było jasne, który jest który
        self.episodes = []
        t = self.start_time + WARMUP
        for index, name in enumerate(scenarios):
            defaults = SCENARIO_DEFAULTS[name]
            self.episodes.append({
                "episode_id": f"{name}-{index + 1}",
                "scenario": name,
                "start": t,
                "end": t + defaults["duration"],
                "rate": defaults["rate"] * anomaly_scale,
            })
            t += defaults["duration"] + GAP

        needed = t - self.start_time if self.episodes else 0
        if needed > duration:
            logger.warning(f"Requested duration {duration}s is too short for the selected scenarios, extending to {needed}s")
        self.duration = max(duration, needed)
        self.end_time = self.start_time + self.duration

    def _labelled(self, flows, label, episode=None):
        for flow in flows:
            if episode is not None:
                episode["flow_count"] += 1
            yield SimulatedFlow(flow, label, episode["episode_id"] if episode else None)

    def flows(self):
        """Zwraca wszystkie przepływy z symulacji (SimulatedFlow), posortowane po czasie rozpoczęcia."""
        rng = random.Random(self.seed)
        streams = [self._labelled(normal_traffic(rng, self.start_time, self.end_time, self.rate), "normal")]
        for episode in self.episodes:
            info, flows = SCENARIOS[episode["scenario"]](rng, episode["start"], episode["end"], episode["rate"])
            episode.update(info, flow_count=0)
            streams.append(self._labelled(flows, episode["scenario"], episode))
        return heapq.merge(*streams, key=lambda f: f.flow.start_timestamp)

    def ground_truth(self):
        """Opis tego, co faktycznie wygenerowałyśmy - przyda się do liczenia precision/recall."""
        return {
            "seed": self.seed,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "normal_rate": self.rate,
            "anomaly_scale": self.anomaly_scale,
            "episodes": [dict(e) for e in self.episodes],
        }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="NetGuard traffic simulator (synthetic laboratory traffic only)")
    parser.add_argument("--scenario", action="append", default=[], choices=list(SCENARIOS) + ["all"],
                        help="Anomalous scenario to inject (repeatable). Without it only normal traffic is generated.")
    parser.add_argument("--rate", type=float, default=200, help="Normal traffic rate in flows/s (default: 200)")
    parser.add_argument("--duration", type=float, default=60.0, help="Simulated duration in seconds (default: 60)")
    parser.add_argument("--anomaly-scale", type=float, default=1.0, help="Multiplier for all scenario rates (default: 1.0)")
    parser.add_argument("--seed", type=int, help="Random seed for a reproducible run")
    parser.add_argument("--output", default="output/simulated_flows.jsonl", help="Generated flows (JSON Lines)")
    parser.add_argument("--ground-truth", default="output/ground_truth.json", help="Ground-truth episodes (JSON)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    scenarios = list(SCENARIOS) if "all" in args.scenario else list(dict.fromkeys(args.scenario))
    simulator = TrafficSimulator(scenarios=scenarios, rate=args.rate, duration=args.duration,
                                 anomaly_scale=args.anomaly_scale, seed=args.seed)

    for path in (args.output, args.ground_truth):
        if os.path.dirname(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)

    logger.info(f"Starting simulation: normal rate={simulator.rate} flows/s, duration={simulator.duration}s, "
                f"scenarios={scenarios or 'none'}, anomaly scale={simulator.anomaly_scale}, seed={simulator.seed}")
    flow_counts = Counter()
    with open(args.output, "w", encoding="utf-8") as out:
        for sim_flow in simulator.flows():
            out.write(json.dumps(sim_flow.flow.to_dict()) + "\n")
            flow_counts[sim_flow.label] += 1

    ground_truth = simulator.ground_truth()
    ground_truth["flow_counts"] = dict(flow_counts)
    with open(args.ground_truth, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)
    logger.info(f"Simulation finished: {sum(flow_counts.values())} flows written to {args.output}, "
                f"ground truth written to {args.ground_truth}")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    main()
