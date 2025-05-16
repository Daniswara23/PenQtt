import paho.mqtt.client as mqtt
import time

class QoSTester:
    def __init__(self, broker_ip, username=None, password=None, retain=False, delay=0.005, logger=None):
        self.broker_ip = broker_ip
        self.username = username
        self.password = password
        self.retain = retain
        self.delay = delay
        self.result = {}
        self.logger = logger

    def log(self, message):
        if self.logger:
            self.logger(message)

    def run(self):
        import paho.mqtt.client as mqtt, time
        qos_levels = [0, 1, 2]
        topic_stages = [100, 250, 500, 1000]

        for qos_level in qos_levels:
            self.log(f"[+] QoS {qos_level} testing...")
            client = mqtt.Client()
            if self.username and self.password:
                client.username_pw_set(self.username, self.password)

            try:
                client.connect(self.broker_ip, 1883, 60)
                client.loop_start()
                time.sleep(1)

                max_delay = 0
                topic_base = f"qos{qos_level}"
                start_time = time.time()
                stage_index = 0

                while time.time() - start_time < 60 and stage_index < len(topic_stages):
                    current_topics = topic_stages[stage_index]
                    stage_index += 1
                    topics = []

                    for i in range(current_topics):
                        topic = f"{topic_base}/topic{i}"
                        client.subscribe(topic, qos=qos_level)
                        topics.append(topic)
                        time.sleep(self.delay)

                    for topic in topics:
                        payload = f"QoS_TEST_{topic}"
                        t0 = time.time()
                        result = client.publish(topic, payload, qos=qos_level, retain=self.retain)
                        if qos_level > 0:
                            result.wait_for_publish()
                        pub_delay = time.time() - t0
                        max_delay = max(max_delay, pub_delay)

                client.loop_stop()
                client.disconnect()
                self.result[qos_level] = max_delay
                self.log(f"[✓] QoS {qos_level} selesai | Max Delay: {max_delay:.3f}s")
            except Exception as e:
                self.log(f"[!] QoS {qos_level} gagal - {e}")
                self.result[qos_level] = -1

        return self.result
