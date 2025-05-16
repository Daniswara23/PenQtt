from core.global_state import sniffed_topics, brute_force_credentials
from colorama import Fore, Style
import time
import paho.mqtt.client as mqtt

def mqtt_enum_broker(broker_ip, username=None, password=None):
    print(f"{Fore.GREEN}[*] Menghubungi broker MQTT di {broker_ip}:1883{Style.RESET_ALL}")

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print(f"{Fore.GREEN}[+] Berhasil terhubung ke broker!{Style.RESET_ALL}")
            client.subscribe("#")
        else:
            print(f"{Fore.RED}[-] Koneksi ditolak, kode: {rc}{Style.RESET_ALL}")
            client.disconnect()  # Stop, brute force dilakukan di main()

    def on_message(client, userdata, msg):
        print(f"{Fore.CYAN}[MQTT] Topic: {msg.topic} | Payload: {msg.payload.decode(errors='ignore')}{Style.RESET_ALL}")
        sniffed_topics.add(msg.topic)

    client = mqtt.Client()
    if username and password:
        client.username_pw_set(username, password)
    else:
        # fallback ke hasil brute force jika ada
        if brute_force_credentials["username"] and brute_force_credentials["password"]:
            client.username_pw_set(
                brute_force_credentials["username"],
                brute_force_credentials["password"]
            )

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(broker_ip, 1883, 60)
        client.loop_start()
        time.sleep(30)  # kasih waktu sniff lebih panjang (bisa 30-60 detik)
        client.loop_stop()
        client.disconnect()
        print(f"{Fore.GREEN}[✓] Sniffing selesai untuk broker {broker_ip}.{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error koneksi ke broker {broker_ip}: {e}{Style.RESET_ALL}")


