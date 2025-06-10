import nmap
from agent.config import Config
import logging
from fastapi import HTTPException

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NmapScanner:
    def __init__(self, targets="127.0.0.1", ports="1-1024"):
        self.nm = nmap.PortScanner()
        cfg = Config.load()
        self.targets = cfg.scan.get('targets', targets)
        self.ports = cfg.scan.get('ports', ports)
        self.scan_type = cfg.scan.get('scan_type', '-sT -T4')

    def scan(self, arguments=None):
        try:
            arguments = arguments or self.scan_type
            print(f"[+] Scanning {self.targets} on ports {self.ports} with {arguments}")
            result = self.nm.scan(hosts=self.targets,
                              ports=self.ports,
                              arguments=arguments)
            return result
        except nmap.PortScannerError as e:
            raise HTTPException(status_code=400, detail=f"Scan failed: {str(e)}")