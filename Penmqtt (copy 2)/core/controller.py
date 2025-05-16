from core.network_scanner import NetworkScanner
from core.sniffer import Sniffer
from core.mqtt_enum import MQTTEnumerator
from core.brute_force import BruteForcer
from core.fuzzer import Fuzzer
from core.qos_delay import QoSTester
from core.dos_flodder import DoSFlooder
from core.report import ReportGenerator

class PenTestController:
    def __init__(self, logger=None):
        self.logger = logger
        self.interface = None
        self.credentials = (None, None)
        self.topics = []
        self.qos_summary = {}
        self.broker_ip = None

    def log(self, msg):
        if self.logger:
            self.logger(msg)
    
    def run_full_pentest(self, selected_ip=None):

        # 1. Inisialisasi scanner
        scanner = NetworkScanner(logger=self.logger)
        self.interface = scanner.interface

        if not scanner.scan_network():
            self.log("[!] Scan jaringan gagal.")
            return

        if not scanner.found_devices:
            self.log("[!] Tidak ada perangkat ditemukan.")
            return

        # 2. Pilih perangkat pertama (bisa disesuaikan)
        if selected_ip:
            target_ip = selected_ip
        else:
            target_ip = scanner.found_devices[0]['ip']

        self.log(f"[+] Menargetkan perangkat: {target_ip}")

        # 3. Sniff broker MQTT dari komunikasi perangkat
        sniffer = Sniffer(self.interface)
        sniffer.logger = self.logger
        broker_list = sniffer.sniff_broker_from_iot(target_ip)

        if not broker_list:
            self.log("[!] Tidak ada broker MQTT ditemukan.")
            return

        self.broker_ip = broker_list[0]
        self.log(f"[+] Menggunakan broker: {self.broker_ip}")

        # 4. Enum topic
        enum = MQTTEnumerator(logger=self.logger)
        self.topics = enum.enum(self.broker_ip)

        # 5. Brute force jika belum ada topik
        if not self.topics:
            bruter = BruteForcer(logger=self.logger)
            self.credentials = bruter.brute_force(self.broker_ip)

            if self.credentials:
                username, password = self.credentials
                self.topics = enum.enum(self.broker_ip, username, password)
            else:
                self.log("[!] Brute force gagal, tidak ada kredensial ditemukan.")

        # 6. Fuzzing
        fuzzer = Fuzzer(self.broker_ip, *self.credentials, logger=self.logger)
        fuzzer.run(self.topics)

        # 7. QoS Delay Test
        qos = QoSTester(self.broker_ip, *self.credentials, logger=self.logger)
        self.qos_summary = qos.run()

        # 8. DoS
        dos = DoSFlooder(self.broker_ip, *self.credentials, logger=self.logger)
        dos.run()

        # 9. Generate report
        report = ReportGenerator(f"report_{self.broker_ip.replace('.', '_')}.pdf", logger=self.logger)
        report.generate(
            broker_ip=self.broker_ip,
            username=self.credentials[0],
            password=self.credentials[1],
            topics=self.topics,
            fuzz_count=20,
            flood_info={"topic_count": "1000", "messages_per_topic": "3000"},
            qos_delay_summary=self.qos_summary
        )

        self.log("[✓] Proses pentest selesai.")
