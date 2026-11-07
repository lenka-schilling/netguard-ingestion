"""Profile ruchu dla symulatora NetGuard.

Generatory tworzą tylko sztuczne obiekty Flow - nic nie jest wysyłane do prawdziwej sieci.
Wszystkie adresy wzięłyśmy z puli prywatnej (RFC 1918) albo dokumentacyjnej (RFC 5737),
żeby na pewno nie trafić w niczyj prawdziwy adres.
"""
import math

from src.models import Flow

EPHEMERAL_PORTS = (49152, 65535)

CLIENTS = [f"10.10.1.{i}" for i in range(10, 30)]
SERVERS = [f"10.10.0.{i}" for i in range(10, 15)]
EXTERNALS = [f"203.0.113.{i}" for i in range(10, 20)]
# Do tego adresu normalni klienci nigdy się nie łączą - potrzebny w scenariuszu abnormal_pattern
UNUSUAL_EXTERNAL = "203.0.113.254"
PORT_SCAN_ATTACKER = "198.51.100.23"
BRUTE_FORCE_ATTACKER = "198.51.100.77"
DOS_SOURCES = [f"198.51.100.{i}" for i in range(100, 254)]

# Usługi w ruchu normalnym: (protokół, port, waga, pakiety, bajty na pakiet, czas trwania [s])
# Wagi dobrałyśmy tak, żeby przeważało HTTPS i DNS, jak w zwykłej sieci
NORMAL_SERVICES = [
    ("TCP", 443, 50, (8, 60), (400, 1200), (0.05, 5.0)),
    ("TCP", 80, 15, (6, 40), (300, 1000), (0.05, 3.0)),
    ("UDP", 53, 25, (1, 2), (70, 150), (0.0, 0.05)),
    ("UDP", 123, 4, (1, 2), (90, 90), (0.0, 0.02)),
    ("TCP", 22, 3, (20, 400), (100, 300), (5.0, 120.0)),
    ("TCP", 25, 3, (10, 50), (200, 900), (0.2, 4.0)),
]
HTTPS_SERVICE = NORMAL_SERVICES[0]

# Domyślne ustawienia scenariuszy: ile przepływów na sekundę i jak długo trwa scenariusz [s]
SCENARIO_DEFAULTS = {
    "port_scan": {"rate": 100, "duration": 10},
    "dos": {"rate": 2000, "duration": 15},
    "brute_force": {"rate": 15, "duration": 40},
    "abnormal_pattern": {"rate": 20, "duration": 60},
}


def poisson_times(rng, rate, start, end):
    """Losuje czasy kolejnych przepływów (proces Poissona) ze średnią rate na sekundę, w przedziale [start, end)."""
    t = start
    while True:
        t += rng.expovariate(rate)
        if t >= end:
            return
        yield t


def _flow(ts, src_ip, dst_ip, src_port, dst_port, protocol, duration, packets, byte_count):
    flow = Flow(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
                protocol=protocol, timestamp=ts)
    flow.end_timestamp = ts + duration
    flow.packet_count = packets
    flow.byte_count = byte_count
    return flow


def _service_flow(rng, ts, src_ip, dst_ip, service, multiplier=1, dst_port=None):
    protocol, port, _, packets_range, bytes_range, duration_range = service
    packets = rng.randint(*packets_range)
    low, high = duration_range
    # Losujemy w skali logarytmicznej, żeby było dużo krótkich połączeń i tylko trochę długich
    duration = rng.uniform(low, high) if low <= 0 else math.exp(rng.uniform(math.log(low), math.log(high)))
    return _flow(ts, src_ip, dst_ip, rng.randint(*EPHEMERAL_PORTS), dst_port or port, protocol,
                 duration * multiplier, packets, packets * rng.randint(*bytes_range) * multiplier)


def normal_traffic(rng, start, end, rate):
    """Ruch normalny w tle: klienci łączą się z serwerami i hostami zewnętrznymi na typowych usługach."""
    weights = [service[2] for service in NORMAL_SERVICES]
    destinations = SERVERS + EXTERNALS
    for ts in poisson_times(rng, rate, start, end):
        service = rng.choices(NORMAL_SERVICES, weights=weights)[0]
        yield _service_flow(rng, ts, rng.choice(CLIENTS), rng.choice(destinations), service)


def port_scan(rng, start, end, rate):
    """Port Scan: jedno źródło sprawdza po kolei wiele portów jednego celu, każdy jednym pakietem."""
    target = rng.choice(SERVERS)
    ports = list(range(1, 1025))
    rng.shuffle(ports)
    src_port = rng.randint(*EPHEMERAL_PORTS)

    def flows():
        # Każdy port sprawdzamy tylko raz, więc jak porty się skończą, skan kończy się wcześniej
        for ts, port in zip(poisson_times(rng, rate, start, end), ports):
            yield _flow(ts, PORT_SCAN_ATTACKER, target, src_port, port, "TCP", 0.0, 1, 60)

    return {"src_ips": [PORT_SCAN_ATTACKER], "dst_ips": [target], "dst_ports": "1-1024"}, flows()


def dos(rng, start, end, rate):
    """DoS-like: dużo źródeł naraz otwiera krótkie połączenia do jednej usługi na jednym celu."""
    target = rng.choice(SERVERS)

    def flows():
        for ts in poisson_times(rng, rate, start, end):
            packets = rng.randint(1, 2)
            yield _flow(ts, rng.choice(DOS_SOURCES), target, rng.randint(*EPHEMERAL_PORTS), 80, "TCP",
                        rng.uniform(0.0, 0.001), packets, 60 * packets)

    return {"src_ips": DOS_SOURCES, "dst_ips": [target], "dst_ports": "80"}, flows()


def brute_force(rng, start, end, rate):
    """Brute Force-like: jedno źródło w kółko łączy się z tą samą usługą (SSH) na jednym celu."""
    target = rng.choice(SERVERS)

    def flows():
        for ts in poisson_times(rng, rate, start, end):
            packets = rng.randint(12, 20)
            yield _flow(ts, BRUTE_FORCE_ATTACKER, target, rng.randint(*EPHEMERAL_PORTS), 22, "TCP",
                        rng.uniform(0.3, 2.0), packets, packets * rng.randint(80, 160))

    return {"src_ips": [BRUTE_FORCE_ATTACKER], "dst_ips": [target], "dst_ports": "22"}, flows()


def abnormal_pattern(rng, start, end, rate):
    """Abnormal Connection Pattern: zwykły klient nagle zachowuje się inaczej niż zwykle -
    łączy się częściej, dłużej i wysyła dużo więcej danych do nowego adresu."""
    victim = rng.choice(CLIENTS)

    def flows():
        for ts in poisson_times(rng, rate, start, end):
            yield _service_flow(rng, ts, victim, UNUSUAL_EXTERNAL, HTTPS_SERVICE, multiplier=10, dst_port=8443)

    return {"src_ips": [victim], "dst_ips": [UNUSUAL_EXTERNAL], "dst_ports": "8443"}, flows()


SCENARIOS = {
    "port_scan": port_scan,
    "dos": dos,
    "brute_force": brute_force,
    "abnormal_pattern": abnormal_pattern,
}
