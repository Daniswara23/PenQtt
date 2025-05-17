import random
import string
import paho.mqtt.client as mqtt

class Fuzzer:
    def __init__(self, broker_ip, username=None, password=None, logger=None):
        self.broker_ip = broker_ip
        self.username = username
        self.password = password
        self.logger = logger

    def log(self, message):
        if self.logger:
            self.logger(message)

    def generate_payload(self, length=256):
        import random, string
        chars = string.ascii_letters + string.digits + string.punctuation + ''.join(chr(i) for i in range(32))
        return ''.join(random.choice(chars) for _ in range(length))

    def run(self, topics=None, iterations=20):
        import paho.mqtt.client as mqtt
        topics = topics or ["fuzz/test"]
        client = mqtt.Client()
        if self.username and self.password:
            client.username_pw_set(self.username, self.password)

        try:
            client.connect(self.broker_ip, 1883, 60)
            client.loop_start()

            for i in range(iterations):
                topic = random.choice(topics)
                payload = self.generate_payload()
                client.publish(topic, payload)
                self.log(f"[Fuzz] Sent to {topic} | Payload: {payload[:30]}...")

            client.loop_stop()
            client.disconnect()
        except Exception as e:
            self.log(f"[!] Gagal koneksi/publish: {e}")

