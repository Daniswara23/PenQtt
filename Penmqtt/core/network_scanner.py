import netifaces
import ipaddress
import nmap
from colorama import Fore, Style
from prettytable import PrettyTable

class NetworkScanner:
    def __init__(self, logger=None):
        self.interface = self.get_active_interface()
        self.found_devices = []
        self.logger = logger

    def log(self, message):
        if self.logger:
            self.logger(message)
    def get_active_interface(self):
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if iface.startswith('lo'):
                continue
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                return iface
        raise RuntimeError("Tidak ditemukan interface aktif!")

    def get_network_cidr(self, iface):
        addrs = netifaces.ifaddresses(iface)
        ip_info = addrs[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
        network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
        return str(network)

    def scan_network(self):
        iface = self.interface
        network_cidr = self.get_network_cidr(iface)
        print(f"{Fore.CYAN}[*] Memulai pemindaian pada {network_cidr}...{Style.RESET_ALL}")
        nm = nmap.PortScanner()
        nm.scan(hosts=network_cidr, arguments="-sn")

        table = PrettyTable()
        table.field_names = ["No", "IP Address", "MAC Address", "Vendor"]
        self.found_devices = []

        no = 1
        for host in nm.all_hosts():
            mac = nm[host]['addresses'].get('mac', 'Unknown MAC')
            vendor = nm[host]['vendor'].get(mac, 'Unknown Vendor')
            device_info = {"ip": host, "mac": mac, "vendor": vendor, "name": host}
            self.found_devices.append(device_info)
            table.add_row([no, host, mac, vendor])
            no += 1

        print(f"\n[+] Pemindaian selesai. {len(self.found_devices)} perangkat ditemukan.")
        print(table)
        return True

    def scan_mqtt_ports(self):
        network_cidr = self.get_network_cidr(self.interface)
        print(f"{Fore.CYAN}[*] Memindai jaringan untuk port MQTT (1883, 8883)...{Style.RESET_ALL}")
        nm = nmap.PortScanner()
        nm.scan(hosts=network_cidr, arguments="-p 1883,8883 --open")
        mqtt_hosts = []
        for host in nm.all_hosts():
            if 'tcp' in nm[host]:
                if 1883 in nm[host]['tcp'] or 8883 in nm[host]['tcp']:
                    mqtt_hosts.append(host)

        self.log(f"[✓] MQTT broker ditemukan: {mqtt_hosts}")
        return mqtt_hosts

    def get_device_details(self, ip, callback=None):
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip, arguments='-O -sV')  # Scan OS dan service version
            host_info = nm[ip]

            mac = host_info['addresses'].get('mac', 'Unknown MAC')
            vendor = host_info.get('vendor', {}).get(mac, 'Unknown Vendor')
            os_name = host_info.get('osmatch', [{}])[0].get('name', 'Unknown OS')

            ports = []
            for proto in host_info.get('tcp', {}):
                port = host_info['tcp'][proto]
                ports.append({
                    "number": proto,
                    "protocol": "tcp",
                    "state": port.get('state', ''),
                    "service": port.get('name', ''),
                    "product": port.get('product', ''),
                    "version": port.get('version', '')
                })

            result = {
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "os": os_name,
                "ports": ports
            }

            if callback:
                callback(result)
            else:
                return result

        except Exception as e:
            if callback:
                callback(None)
            else:
                return None


