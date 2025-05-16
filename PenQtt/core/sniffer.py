from colorama import Fore, Style
from scapy.all import sniff, IP, TCP
from core.network_scanner import get_network_cidr, scan_mqtt_ports

def sniff_broker_from_iot(iot_ip, interface, duration=30):
    print(f"{Fore.YELLOW}[*] Mendeteksi broker yang berkomunikasi dengan {iot_ip}...{Style.RESET_ALL}")
    broker_ips = set()

    print(f"{Fore.CYAN}[*] Sniffing komunikasi MQTT selama {duration} detik...{Style.RESET_ALL}")

    def packet_callback(pkt):
        if IP in pkt and TCP in pkt:
            if pkt[TCP].dport in [1883, 8883]:
                broker_ips.add(pkt[IP].dst)
            elif pkt[TCP].sport in [1883, 8883]:
                broker_ips.add(pkt[IP].src)

    sniff(iface=interface, filter="tcp port 1883 or tcp port 8883", prn=packet_callback, timeout=duration)

    if not broker_ips:
        network_cidr = get_network_cidr(interface)
        mqtt_hosts = scan_mqtt_ports(network_cidr)
        broker_ips.update(mqtt_hosts)

    return list(broker_ips)
