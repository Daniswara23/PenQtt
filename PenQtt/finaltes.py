#!/usr/bin/env python3
import os
import sys
import time
import nmap
import netifaces
import ipaddress
import paho.mqtt.client as mqtt
import random
import string
import threading
import statistics
from scapy.all import sniff, IP, TCP, send, RandShort
from colorama import Fore, Style, init
from prettytable import PrettyTable
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime


init()

sniffed_topics = set()
brute_force_credentials = {"username": None, "password": None}

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{Fore.RED}Jalankan dengan sudo!{Style.RESET_ALL}")
        sys.exit(1)

    iface = get_active_interface()
    iot_devices = scan_network(iface)

    if not iot_devices:
        print(f"{Fore.RED}[-] Tidak ada perangkat IoT ditemukan.{Style.RESET_ALL}")
        sys.exit(0)

    choice = int(input(f"\n{Fore.CYAN}[?] Pilih nomor perangkat (1-{len(iot_devices)}): {Style.RESET_ALL}"))
    if 1 <= choice <= len(iot_devices):
        selected_ip = iot_devices[choice - 1]
        brokers = sniff_broker_from_iot(selected_ip, iface)

        if not brokers:
            print(f"{Fore.YELLOW}[*] Tidak ditemukan broker MQTT dari perangkat tersebut.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Mencoba scan jaringan untuk broker MQTT...{Style.RESET_ALL}")
            network_cidr = get_network_cidr(iface)
            brokers = scan_mqtt_ports(network_cidr)

        if brokers:
            print(f"{Fore.GREEN}[+] Broker MQTT ditemukan: {brokers}{Style.RESET_ALL}")
            for broker_ip in brokers:
                # coba enum langsung
                mqtt_enum_broker(broker_ip)

                # jika tidak ada topik, mungkin butuh brute force + reconnect
                if not sniffed_topics:
                    do_brute = input(f"{Fore.YELLOW}[?] Broker {broker_ip} membutuhkan login? Lakukan brute force? (y/n): {Style.RESET_ALL}")
                    if do_brute.lower() == 'y':
                        result = mqtt_brute_force_combined(broker_ip)
                        if result:
                            mqtt_enum_broker(
                                broker_ip,
                                username=brute_force_credentials["username"],
                                password=brute_force_credentials["password"]
                            )

                # tampilkan hasil sniffing
                if sniffed_topics:
                    print(f"{Fore.GREEN}[+] Hasil Topik MQTT yang di-sniffing:{Style.RESET_ALL}")
                    for topic in sniffed_topics:
                        print(f" - {topic}")
                else:
                    print(f"{Fore.RED}[-] Tidak ada topik yang di-sniff.{Style.RESET_ALL}")

                # serangan tambahan
                do_fuzz = input(f"{Fore.YELLOW}[?] Lakukan MQTT Fuzzing ke {broker_ip}? (y/n): {Style.RESET_ALL}")
                if do_fuzz.lower() == 'y':
                    mqtt_fuzz_broker(
                        broker_ip,
                        username=brute_force_credentials["username"],
                        password=brute_force_credentials["password"]
                    )

                do_qos = input(f"{Fore.YELLOW}[?] Lakukan MQTT QoS Delay Test ke {broker_ip}? (y/n): {Style.RESET_ALL}")
                if do_qos.lower() == 'y':
                    mqtt_qos_delay_test(
                        broker_ip,
                        username=brute_force_credentials["username"],
                        password=brute_force_credentials["password"]
                    )

                do_flood = input(f"{Fore.YELLOW}[?] Lakukan Subscribe + Publish Flood ke {broker_ip}? (y/n): {Style.RESET_ALL}")
                if do_flood.lower() == 'y':
                    mqtt_subscribe_publish(broker_ip)

                do_report = input(f"{Fore.YELLOW}[?] Buatkan laporan PDF untuk {broker_ip}? (y/n): {Style.RESET_ALL}")
                if do_report.lower() == 'y':
                    generate_pdf_report(
                        broker_ip=broker_ip,
                        username=brute_force_credentials["username"],
                        password=brute_force_credentials["password"],
                        topics=sniffed_topics,
                        fuzz_count=20,
                        flood_info={"topic_count": "1000", "messages_per_topic": "3000"},
                        qos_delay_summary={"0": 0.0, "1": 0.0, "2": 0.0}
                    )
        else:
            print(f"{Fore.RED}[-] Tidak ada broker MQTT ditemukan di jaringan.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] Pilihan tidak valid.{Style.RESET_ALL}")
