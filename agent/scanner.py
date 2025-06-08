import nmap

class NmapScanner:
    def __init__(self, targets="127.0.0.1", ports="1-1024"):
        self.nm = nmap.PortScanner()
        self.targets = targets
        self.ports = ports

    def scan(self, arguments="-sS -T4"):
        """
        Run a TCP SYN scan with default timing;
        returns a dict of hosts → ports → state info.
        """
        print(f"[+] Scanning {self.targets} on ports {self.ports}")
        result = self.nm.scan(hosts=self.targets,
                              ports=self.ports,
                              arguments=arguments)
        return result

if __name__ == "__main__":
    scanner = NmapScanner(targets="192.168.1.0/24", ports="22,80,443")
    out = scanner.scan()
    print(out)
