import logging
from src.extractor import extract_flows
from src.stream_processor.windows import WindowProcessor
from src.config import Config, WindowsConfig
from src.detection.engine import DetectionEngine

logger = logging.getLogger("NetGuard.Main")

def run_pipeline(pcap_path: str):
    logger.info("=== STARTING NETGUARD ===")
    
    # 1. Konfiguracja i Inicjalizacja
    config = Config(windows=WindowsConfig(sizes_s=[1, 10, 60], lateness_s=5.0))
    engine = DetectionEngine(config)
    processor = WindowProcessor("src_ip", lateness_s=5.0)

    # 2. Ekstrakcja (Tydzień 3)
    logger.info(f"Krok 1: Loading and extraction from {pcap_path}")
    flows = extract_flows(pcap_path)
    if not flows:
        logger.warning("No data for analysis.")
        return

    # 3. Stream Processing & Agregacja (Tydzień 4)
    logger.info("Krok 2: Agregation in time frames...")
    all_windows = []
    for flow in flows:
        all_windows.extend(processor.add(flow))
    all_windows.extend(processor.flush())
    
    # 4. Detekcja Anomalii (Tydzień 5)
    logger.info("Krok 3: Skanning using detection engine...")
    all_alerts = []
    for window in all_windows:
        all_alerts.extend(engine.process(window))

    # 5. Wyniki (Tymczasowe, docelowo trafią na Brokera i do Bazy)
    logger.info(f"=== FINISHED. Encountered alerts: {len(all_alerts)} ===")
    for alert in all_alerts:
        print(f"\n ALARM: {alert.type} ({alert.severity})")
        print(f"   Certainty: {alert.confidence}")
        print(f"   Source: {alert.source}")
        print(f"   Explanation: {alert.explanation}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    
    # Ścieżka do Twojego pliku testowego
    test_file = "data/tcp-ethereal-file1.trace"
    run_pipeline(test_file)