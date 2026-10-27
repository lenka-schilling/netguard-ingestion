import logging
import dpkt

logger = logging.getLogger("NetGuard.Importer")

def load_pcap_file(file_path: str):
    logger.info(f"Attempting to open and validate PCAP file: {file_path}")

    try:
        file_obj = open(file_path, 'rb')
        pcap_reader = dpkt.pcap.Reader(file_obj)
        logger.info(f"Successfully loaded and validated header for: {file_path}")
        return file_obj, pcap_reader
    except FileNotFoundError:
        logger.error(f"Import failed: File '{file_path}' not found")
        raise
    except Exception as e:
        logger.error(f"Import validation failed for '{file_path}': Invalid file format or corrupted header ({e})")
        raise