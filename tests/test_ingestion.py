import os
import socket
import unittest
from src.models import Flow
from src.importer import load_pcap_file
from src.extractor import inet_to_str, is_valid_port, extract_flows


class TestNetGuardIngestion(unittest.TestCase):

    # 1. Test modelu Flow (src/models.py)
    def test_flow_model_to_dict_and_duration(self):
        """Sprawdza, czy model Flow poprawnie liczy duration i tworzy słownik."""
        flow = Flow(
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol="TCP",
            timestamp=1000.0
        )
        flow.end_timestamp = 1002.5
        flow.packet_count = 3
        flow.byte_count = 450

        result = flow.to_dict()

        self.assertEqual(result["src_ip"], "192.168.1.10")
        self.assertEqual(result["dst_ip"], "10.0.0.1")
        self.assertEqual(result["src_port"], 54321)
        self.assertEqual(result["dst_port"], 80)
        self.assertEqual(result["protocol"], "TCP")
        self.assertEqual(result["duration"], 2.5)
        self.assertEqual(result["packet_count"], 3)
        self.assertEqual(result["byte_count"], 450)
        self.assertIn("flow_id", result)
        self.assertIn("ingested_at", result)

    # 2. Test walidacji portów (src/extractor.py)
    def test_is_valid_port(self):
        """Sprawdza poprawność walidacji zakresu portów (0-65535)."""
        self.assertTrue(is_valid_port(0))
        self.assertTrue(is_valid_port(80))
        self.assertTrue(is_valid_port(65535))
        self.assertFalse(is_valid_port(-1))
        self.assertFalse(is_valid_port(65536))
        self.assertFalse(is_valid_port("80"))
        self.assertFalse(is_valid_port(None))

    # 3. Test konwersji binarnego IP na tekst (src/extractor.py)
    def test_inet_to_str(self):
        """Sprawdza konwersję binarnego adresu IPv4 i obsługę błędnych danych."""
        raw_ipv4 = socket.inet_pton(socket.AF_INET, "127.0.0.1")
        self.assertEqual(inet_to_str(raw_ipv4), "127.0.0.1")
        self.assertIsNone(inet_to_str(b"invalid_bytes"))

    # 4. Test importera dla nieistniejącego pliku (src/importer.py)
    def test_load_pcap_file_not_found(self):
        """Sprawdza, czy importer rzuca wyjątek FileNotFoundError dla brakującego pliku."""
        with self.assertRaises(FileNotFoundError):
            load_pcap_file("data/plik_ktory_nie_istnieje.pcap")

    # 5. Test ekstrakcji na poprawnym pliku PCAP (src/extractor.py)
    def test_extract_flows_valid_pcap(self):
        """Sprawdza pełną ekstrakcję przepływów z poprawnego pliku data/sample.pcap."""
        sample_path = os.path.join("data", "sample.pcap")
        if not os.path.exists(sample_path):
            self.skipTest("Brak pliku data/sample.pcap")

        flows = extract_flows(sample_path)

        self.assertIsInstance(flows, list)
        self.assertGreater(len(flows), 0, "Powinien zostać wyodrębniony przynajmniej jeden flow")

        first_flow = flows[0]
        required_keys = {
            "flow_id", "ingested_at", "start_timestamp", "duration",
            "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "packet_count", "byte_count"
        }
        self.assertTrue(required_keys.issubset(first_flow.keys()))
        self.assertGreaterEqual(first_flow["packet_count"], 1)
        self.assertGreater(first_flow["byte_count"], 0)

    # 6. Test odporności na uszkodzony plik PCAP (src/extractor.py)
    def test_extract_flows_corrupted_pcap_does_not_crash(self):
        """Sprawdza, czy uszkodzony plik (data/corrupted.pcap) nie wywala programu."""
        corrupted_path = os.path.join("data", "corrupted.pcap")
        if not os.path.exists(corrupted_path):
            self.skipTest("Brak pliku data/corrupted.pcap")

        # Funkcja powinna obsłużyć błąd i zwrócić listę (nie rzucić wyjątku)
        flows = extract_flows(corrupted_path)
        self.assertIsInstance(flows, list)

    # 7. Test ekstrakcji, gdy plik nie istnieje (src/extractor.py)
    def test_extract_flows_missing_file_returns_empty_list(self):
        """Sprawdza, czy extract_flows zwraca pustą listę [], gdy plik wejściowy nie istnieje."""
        flows = extract_flows("data/nie_ma_takiego_pliku.pcap")
        self.assertEqual(flows, [])


if __name__ == "__main__":
    unittest.main()