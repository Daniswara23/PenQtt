import paho.mqtt.client as mqtt

class MQTTEnumerator:
    def __init__(self, logger=None):
        self.sniffed_topics = set()
        self.logger = logger

    def log(self, message):
        if self.logger:
            self.logger(message)

    def enum(self, broker_ip, username=None, password=None, duration=30):
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                client.subscribe("#")
            else:
                client.disconnect()

        def on_message(client, userdata, msg):
            self.sniffed_topics.add(msg.topic)
            self.log(f"[Sniffed] {msg.topic}")

        client = mqtt.Client()
        if username and password:
            client.username_pw_set(username, password)

        client.on_connect = on_connect
        client.on_message = on_message

        try:
            client.connect(broker_ip, 1883, 60)
            client.loop_start()
            import time
            time.sleep(duration)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            print(f"Error: {e}")

        self.log(f"[✓] Selesai enum broker {broker_ip}")
        return list(self.sniffed_topics)
