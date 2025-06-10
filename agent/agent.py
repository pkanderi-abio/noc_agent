# File: agent/agent.py
import asyncio
import click
import logging
from agent.scanner import NmapScanner
from agent.capture import PacketCapture
from agent.auth import get_current_user
from agent.db import init_db

logger = logging.getLogger("noc_agent")

async def async_main():
    """
    Core agent loop: runs scanning and packet capture concurrently.
    """
    scanner = NmapScanner()
    capture = PacketCapture()

    async def run_scan_loop():
        logger.info("Starting network scan...")
        try:
            result = scanner.scan()
            logger.info(f"Scan result: {result}")
        except Exception as e:
            logger.error(f"Scan error: {e}")

    async def run_capture_loop():
        logger.info("Starting packet capture...")
        def callback(pkt):
            logger.info(f"Captured packet: {pkt.summary()}")
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, capture.start, callback)
        except Exception as e:
            logger.error(f"Capture error: {e}")

    await asyncio.gather(
        run_scan_loop(),
        run_capture_loop()
    )

@click.command()
@click.option(
    "--mode", type=click.Choice(["agent", "server"]), default="agent",
    help="Mode to run: agent or server."
)
def main(mode):
    """
    noc-agent CLI entry point.
    """
    if mode == "agent":
        # Run the asynchronous agent loop
        asyncio.run(async_main())
    else:
        # Launch FastAPI server synchronously
        init_db()
        from uvicorn import run
        run(
            "agent.api:app",
            host="0.0.0.0",
            port=8000,
            reload=True
        )

if __name__ == "__main__":
    main()
