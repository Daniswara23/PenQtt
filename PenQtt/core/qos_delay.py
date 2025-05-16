def mqtt_qos_delay_test(broker_ip, username=None, password=None, retain=False, delay=0.005):
    from time import time, sleep
    print(f"{Fore.YELLOW}[*] Menjalankan MQTT QoS Delay Test ke {broker_ip}...{Style.RESET_ALL}")

    qos_levels = [0, 1, 2]
    topic_stages = [100, 250, 500, 1000]
    max_publish_delay = {}

    # Ambil dari brute force jika kosong
    username = username or brute_force_credentials["username"]
    password = password or brute_force_credentials["password"]

    for qos_level in qos_levels:
        print(f"{Fore.CYAN}[+] QoS {qos_level} testing...{Style.RESET_ALL}")
        client = mqtt.Client()
        if username and password:
            client.username_pw_set(username, password)

        try:
            client.connect(broker_ip, 1883, 60)
            client.loop_start()
            sleep(1)

            start_time = time()
            stage_index = 0
            topic_base = f"flood/qos{qos_level}"
            max_delay = 0

            while time() - start_time < 60:
                if stage_index >= len(topic_stages):
                    break
                current_topics = topic_stages[stage_index]
                stage_index += 1

                topics = []
                for i in range(current_topics):
                    topic = f"{topic_base}/topic{i}"
                    client.subscribe(topic, qos=qos_level)
                    topics.append(topic)
                    sleep(delay)

                for topic in topics:
                    payload = f"FLOOD_{topic}"
                    t0 = time()
                    result = client.publish(topic, payload, qos=qos_level, retain=retain)
                    if qos_level > 0:
                        result.wait_for_publish()
                    t1 = time()
                    pub_delay = t1 - t0
                    max_delay = max(max_delay, pub_delay)
                    if time() - start_time > 60:
                        break

            client.loop_stop()
            client.disconnect()
            max_publish_delay[qos_level] = max_delay
            print(f"{Fore.GREEN}[✓] QoS {qos_level} selesai | Max Delay: {max_delay:.3f}s{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] QoS {qos_level} gagal - {e}{Style.RESET_ALL}")
            max_publish_delay[qos_level] = -1

    print(f"{Fore.MAGENTA}=== Ringkasan Delay per QoS ==={Style.RESET_ALL}")
    for qos in qos_levels:
        d = max_publish_delay[qos]
        print(f"QoS {qos} : {'Gagal' if d == -1 else f'{d:.3f} detik'}")

    return max_publish_delay
