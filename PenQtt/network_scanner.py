import os
import sys
import time
import nmap
import netifaces
import ipaddress
import threading
from scapy.all import sniff, IP, TCP

class NetworkScanner:
    def __init__(self):
        self.scanning = False
        self.found_devices = []
        self.active_interface = None
        self.scan_lock = threading.Lock()
        
    def get_active_interface(self):
        """Get the name of the active network interface"""
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if iface.startswith('lo'):
                continue
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                return iface
        print("[!] No active interface found!")
        return None

    def get_network_cidr(self, iface):
        """Get network CIDR from the given interface"""
        addrs = netifaces.ifaddresses(iface)
        ip_info = addrs[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
        network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
        return str(network)

    def scan_network(self):
        """
        Scan the network for devices
        Returns True if scan started, False if another scan is in progress
        """
        # Check if a scan is already running
        with self.scan_lock:
            if self.scanning:
                return False
            self.scanning = True
        
        # Clear previous results
        self.found_devices = []
        
        # Start scan in a separate thread
        try:
            # Get the active interface
            self.active_interface = self.get_active_interface()
            if not self.active_interface:
                print("No active network interface found")
                with self.scan_lock:
                    self.scanning = False
                return False
            
            # Get network CIDR
            network_cidr = self.get_network_cidr(self.active_interface)
            print(f"[*] Starting scan on {network_cidr}...")
            
            # Perform the scan
            nm = nmap.PortScanner()
            nm.scan(hosts=network_cidr, arguments="-sn")
            
            # Process results
            for host in nm.all_hosts():
                try:
                    # Get MAC address and vendor info
                    mac = nm[host]['addresses'].get('mac', 'Unknown')
                    vendor = nm[host]['vendor'].get(mac, 'Unknown')
                    
                    # Get hostname if available
                    hostname = nm[host].get('hostnames', [{'name': host}])[0].get('name', host)
                    
                    # Add to device list
                    self.found_devices.append({
                        'ip': host,
                        'mac': mac,
                        'vendor': vendor,
                        'name': hostname if hostname != host else f"Device-{len(self.found_devices)+1}"
                    })
                except Exception as e:
                    print(f"Error processing host {host}: {e}")
                    
            print(f"[+] Scan complete. Found {len(self.found_devices)} devices.")
            
            # Scan complete
            with self.scan_lock:
                self.scanning = False
            
            return True
            
        except Exception as e:
            print(f"Error during network scan: {e}")
            with self.scan_lock:
                self.scanning = False
            return False

    def get_device_details(self, ip_address, callback=None):
        """
        Get detailed information about a specific device
        If callback is provided, it will be called with the results
        """
        try:
            print(f"[*] Getting details for {ip_address}...")
            nm = nmap.PortScanner()
            
            # Run a more detailed scan on the target
            nm.scan(hosts=ip_address, arguments='-sS -sV -O -p-')
            
            # Prepare result
            result = {
                'ip': ip_address,
                'mac': 'Unknown',
                'vendor': 'Unknown',
                'os': 'Unknown',
                'ports': []
            }
            
            if ip_address in nm.all_hosts():
                host_data = nm[ip_address]
                
                # Get MAC and vendor
                if 'mac' in host_data['addresses']:
                    result['mac'] = host_data['addresses']['mac']
                    if result['mac'] in host_data['vendor']:
                        result['vendor'] = host_data['vendor'][result['mac']]
                
                # Get OS details
                if 'osmatch' in host_data and len(host_data['osmatch']) > 0:
                    result['os'] = host_data['osmatch'][0]['name']
                
                # Get open ports
                if 'tcp' in host_data:
                    for port_num, port_data in host_data['tcp'].items():
                        if port_data['state'] == 'open':
                            port_info = {
                                'number': port_num,
                                'protocol': 'tcp',
                                'state': port_data['state'],
                                'service': port_data['name'],
                                'product': port_data.get('product', ''),
                                'version': port_data.get('version', '')
                            }
                            result['ports'].append(port_info)
            
            # Execute callback if provided
            if callback:
                callback(result)
            
            return result
            
        except Exception as e:
            print(f"Error getting device details: {e}")
            if callback:
                callback(None)
            return None