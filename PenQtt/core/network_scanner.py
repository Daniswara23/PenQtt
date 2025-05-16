import netifaces
import ipaddress
import nmap
from colorama import Fore, Style
from prettytable import PrettyTable

def get_active_interface():
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        if iface.startswith('lo'):
            continue
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            return iface
    raise RuntimeError("Tidak ditemukan interface aktif!")

def get_network_cidr(iface):
    addrs = netifaces.ifaddresses(iface)
    ip_info = addrs[netifaces.AF_INET][0]
    ip = ip_info['addr']
    netmask = ip_info['netmask']
    cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
    network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
    return str(network)

def scan_network(iface):
    network_cidr = get_network_cidr(iface)
    print(f"{Fore.CYAN}[*] Memulai pemindaian pada {network_cidr}...{Style.RESET_ALL}")
    nm = nmap.PortScanner()
    nm.scan(hosts=network_cidr, arguments="-sn")

    table = PrettyTable()
    table.field_names = ["No", "IP Address", "MAC Address", "Vendor"]
    devices = []

    no = 1
    for host in nm.all_hosts():
        mac = nm[host]['addresses'].get('mac', 'Unknown MAC')
        vendor = nm[host]['vendor'].get(mac, 'Unknown Vendor')
        devices.append(host)
        table.add_row([no, host, mac, vendor])
        no += 1

    print(f"\n[+] Pemindaian selesai. {len(devices)} perangkat ditemukan.")
    print(table)

    return devices

def scan_mqtt_ports(network_cidr):
    print(f"{Fore.CYAN}[*] Memindai jaringan untuk port MQTT (1883, 8883)...{Style.RESET_ALL}")
    nm = nmap.PortScanner()
    nm.scan(hosts=network_cidr, arguments="-p 1883,8883 --open")
    mqtt_hosts = []
    for host in nm.all_hosts():
        if 'tcp' in nm[host]:
            if 1883 in nm[host]['tcp'] or 8883 in nm[host]['tcp']:
                mqtt_hosts.append(host)
    return mqtt_hosts
