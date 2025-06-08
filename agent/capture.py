from scapy.all import sniff

class PacketCapture:
    def __init__(self, iface=None, bpf_filter=None, count=0):
        """
        iface: e.g., 'eth0' or None for default
        bpf_filter: e.g., 'tcp port 80'
        count: 0 means capture indefinitely
        """
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.count = count

    def start(self, packet_callback):
        """
        Begin sniffing; each packet is passed to packet_callback(pkt).
        """
        print(f"[+] Starting packet capture on {self.iface or 'default'} "
              f"filter={self.bpf_filter}")
        sniff(iface=self.iface,
              filter=self.bpf_filter,
              count=self.count,
              prn=packet_callback)
