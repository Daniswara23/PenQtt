import subprocess
import platform
import re
import socket
from typing import Optional

def get_network_name() -> Optional[str]:
    """
    Get the name of the currently connected network (WiFi or Ethernet).
    
    Returns:
        str or None: The name of the network if connected, None otherwise.
    """
    operating_system = platform.system()
    
    try:
        if operating_system == "Windows":
            # First check WiFi connections
            try:
                wifi_output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode('utf-8')
                wifi_match = re.search(r"SSID\s+:\s+(.+)", wifi_output)
                if wifi_match:
                    return wifi_match.group(1).strip()
            except:
                pass  # WiFi command failed, continue to check Ethernet
            
            # Check Ethernet connections using ipconfig
            try:
                net_config = subprocess.check_output("ipconfig", shell=True).decode('utf-8')
                
                # Find active Ethernet connection
                ethernet_sections = re.findall(r"Ethernet adapter ([^\n:]+):[^\n]*\n(?:.*\n)+?.*IPv4 Address.*: (\d+\.\d+\.\d+\.\d+)", net_config)
                
                if ethernet_sections:
                    # Return the name of the first active Ethernet connection
                    return f"Ethernet: {ethernet_sections[0][0].strip()}"
                
                # Check for other connection types
                other_sections = re.findall(r"([^\n:]+) adapter ([^\n:]+):[^\n]*\n(?:.*\n)+?.*IPv4 Address.*: (\d+\.\d+\.\d+\.\d+)", net_config)
                for section in other_sections:
                    if section[0] != "Ethernet" and section[0] != "Wireless LAN":
                        return f"{section[0]}: {section[1].strip()}"
            except:
                pass
                
        elif operating_system == "Linux":
            # Try nmcli first (Network Manager)
            try:
                output = subprocess.check_output("nmcli -t -f NAME,DEVICE,TYPE connection show --active", shell=True).decode('utf-8')
                if output:
                    # Return the first active connection name
                    conn = output.split('\n')[0].split(':')
                    return conn[0]  # The NAME field
            except:
                pass
                
            # Try using ip command if nmcli fails
            try:
                # Get default interface
                route_output = subprocess.check_output("ip route | grep default | awk '{print $5}'", shell=True).decode('utf-8').strip()
                if route_output:
                    # Check if it's WiFi
                    try:
                        wifi_check = subprocess.check_output(f"iwconfig {route_output} 2>/dev/null", shell=True).decode('utf-8')
                        if "ESSID:" in wifi_check:
                            essid_match = re.search(r'ESSID:"(.+)"', wifi_check)
                            if essid_match:
                                return essid_match.group(1).strip()
                    except:
                        # Not a WiFi interface
                        pass
                    
                    # If not WiFi, return the interface name as the connection name
                    return f"Network: {route_output}"
            except:
                pass
    except Exception as e:
        pass
        
    return None


if __name__ == "__main__":
    # Test the function if this script is run directly
    network_name = get_network_name()
    
    if network_name:
        print(f"Connected to: {network_name}")
    else:
        print("Not connected to any network or unable to determine the network name.")