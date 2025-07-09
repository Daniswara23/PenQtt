from scapy.all import sniff, IP, TCP
from core.network_scanner import NetworkScanner

class Sniffer:
    def __init__(self, interface):
        self.interface = interface
        self.sniffed_brokers = set()

    def sniff_broker_from_iot(self, iot_ip, duration=30):
        def callback(pkt):
            if IP in pkt and TCP in pkt:
                if pkt[TCP].dport in [1883, 8883]:
                    self.sniffed_brokers.add(pkt[IP].dst)
                elif pkt[TCP].sport in [1883, 8883]:
                    self.sniffed_brokers.add(pkt[IP].src)

        sniff(iface=self.interface, filter="tcp port 1883 or 8883", prn=callback, timeout=duration)

        if not self.sniffed_brokers:
            scanner = NetworkScanner()
            self.sniffed_brokers.update(scanner.scan_mqtt_ports())

        return list(self.sniffed_brokers)
