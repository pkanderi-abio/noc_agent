import asyncio
import logging
from agent.config import Config
from agent.scanner import NmapScanner
from agent.capture import PacketCapture
from agent.anomaly import AnomalyDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("noc_agent")

async def scan_loop(scanner, interval):
    while True:
        logger.info("Starting network scan...")
        try:
            result = scanner.scan()
            logger.info(f"Scan result: {result}")
        except Exception as e:
            logger.error(f"Scan error: {e}")
        await asyncio.sleep(interval)

async def capture_loop(capture, callback):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, capture.start, callback)

async def main():
    # Load configuration
    cfg = Config.load()

    scanner = NmapScanner(
        targets=cfg.scan.get('targets'),
        ports=cfg.scan.get('ports')
    )
    capture = PacketCapture(
        iface=cfg.capture.get('iface'),
        bpf_filter=cfg.capture.get('bpf_filter'),
        count=cfg.capture.get('count')
    )
    detector = AnomalyDetector(
        model_path=cfg.anomaly.get('model_path'),
        contamination=cfg.anomaly.get('contamination')
    )

    def packet_callback(pkt):
        summary = pkt.summary()
        logger.info(f"Packet: {summary}")
        # Example feature extraction stub
        features = [len(pkt), pkt.time]
        if detector.detect(features):
            logger.warning("Anomalous packet detected")

    tasks = [
        asyncio.create_task(scan_loop(scanner, cfg.scan.get('interval', 300))),
        asyncio.create_task(capture_loop(capture, packet_callback))
    ]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")