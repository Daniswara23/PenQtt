from core.global_state import sniffed_topics
from colorama import Fore, Style
import random
import string
import paho.mqtt.client as mqtt
import time

def mqtt_fuzz_broker(broker_ip, username=None, password=None, iterations=20):
    print(f"{Fore.YELLOW}[*] Melakukan MQTT fuzzing ke broker {broker_ip}...{Style.RESET_ALL}")
    
    def generate_fuzz_payload():
        length = random.randint(1, 256)
        chars = string.ascii_letters + string.digits + string.punctuation + ''.join(chr(i) for i in range(32))
        return ''.join(random.choice(chars) for _ in range(length))

    client = mqtt.Client()
    if username and password:
        client.username_pw_set(username, password)

    try:
        client.connect(broker_ip, 1883, 60)
        client.loop_start()
        for i in range(iterations):
            if sniffed_topics:
                topic = random.choice(list(sniffed_topics))
            else:
                topic = "fuzz/test"

            payload = generate_fuzz_payload()
            try:
                client.publish(topic, payload)
                print(f"{Fore.CYAN}[Fuzz] Sent to {topic} | Payload: {payload[:30]}...{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Gagal publish ke {topic} - {e}{Style.RESET_ALL}")
            time.sleep(0.2)
        client.loop_stop()
        client.disconnect()
    except Exception as e:
        print(f"{Fore.RED}[!] Gagal koneksi ke broker {broker_ip} - {e}{Style.RESET_ALL}")
