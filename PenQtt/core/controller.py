from core import network_scanner, broker_sniffer, mqtt_enum, mqtt_brute_force, mqtt_fuzzer, qos_tester, flood_attack, report_generator
from core.global_state import sniffed_topics, brute_force_credentials

def run_full_pentest():
    iface = network_scanner.get_active_interface()
    devices = network_scanner.scan_network(iface)

    if not devices:
        raise RuntimeError("Tidak ada perangkat IoT ditemukan di jaringan.")

    selected_ip = devices[0]  # untuk contoh ini, ambil perangkat pertama
    brokers = broker_sniffer.sniff_broker_from_iot(selected_ip, iface)

    if not brokers:
        network_cidr = network_scanner.get_network_cidr(iface)
        brokers = network_scanner.scan_mqtt_ports(network_cidr)

    for broker_ip in brokers:
        mqtt_enum.mqtt_enum_broker(broker_ip)

        if not sniffed_topics:
            mqtt_brute_force.mqtt_brute_force_combined(broker_ip)
            mqtt_enum.mqtt_enum_broker(
                broker_ip,
                username=brute_force_credentials["username"],
                password=brute_force_credentials["password"]
            )

        if sniffed_topics:
            mqtt_fuzzer.mqtt_fuzz_broker(
                broker_ip,
                username=brute_force_credentials["username"],
                password=brute_force_credentials["password"]
            )

            qos_summary = qos_tester.mqtt_qos_delay_test(
                broker_ip,
                username=brute_force_credentials["username"],
                password=brute_force_credentials["password"]
            )

            flood_attack.mqtt_subscribe_publish(
                broker_ip,
                qos=0
            )

            report_generator.generate_pdf_report(
                broker_ip=broker_ip,
                username=brute_force_credentials["username"],
                password=brute_force_credentials["password"],
                topics=sniffed_topics,
                fuzz_count=20,
                flood_info={"topic_count": "1000", "messages_per_topic": "3000"},
                qos_delay_summary=qos_summary
            )
        else:
            print("[-] Tidak ada topik yang berhasil di-sniff.")



from core import network_scanner, broker_sniffer, mqtt_enum, mqtt_brute_force, mqtt_fuzzer, qos_tester, flood_attack, report_generator
from core.global_state import sniffed_topics, brute_force_credentials
from colorama import Fore, Style

def run_cli_controller():
    import sys

    if not hasattr(sys, 'real_prefix') and sys.platform != 'win32':
        import os
        if os.geteuid() != 0:
            print(f"{Fore.RED}Jalankan dengan sudo!{Style.RESET_ALL}")
            sys.exit(1)

    iface = network_scanner.get_active_interface()
    iot_devices = network_scanner.scan_network(iface)

    if not iot_devices:
        print(f"{Fore.RED}[-] Tidak ada perangkat IoT ditemukan.{Style.RESET_ALL}")
        sys.exit(0)

    print("\nPilih perangkat yang ingin dianalisis:")
    for idx, ip in enumerate(iot_devices):
        print(f"{idx+1}. {ip}")

    choice = int(input(f"\n{Fore.CYAN}[?] Pilih nomor perangkat (1-{len(iot_devices)}): {Style.RESET_ALL}"))
    if 1 <= choice <= len(iot_devices):
        selected_ip = iot_devices[choice - 1]
        brokers = broker_sniffer.sniff_broker_from_iot(selected_ip, iface)

        if not brokers:
            print(f"{Fore.YELLOW}[*] Tidak ditemukan broker MQTT dari perangkat tersebut.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Mencoba scan jaringan untuk broker MQTT...{Style.RESET_ALL}")
            network_cidr = network_scanner.get_network_cidr(iface)
            brokers = network_scanner.scan_mqtt_ports(network_cidr)

        if brokers:
            print(f"{Fore.GREEN}[+] Broker MQTT ditemukan: {brokers}{Style.RESET_ALL}")
            for broker_ip in brokers:
                mqtt_enum.mqtt_enum_broker(broker_ip)

                if not sniffed_topics:
                    do_brute = input(f"{Fore.YELLOW}[?] Broker {broker_ip} membutuhkan login? Lakukan brute force? (y/n): {Style.RESET_ALL}")
                    if do_brute.lower() == 'y':
                        result = mqtt_brute_force.mqtt_brute_force_combined(broker_ip)
                        if result:
                            mqtt_enum.mqtt_enum_broker(
                                broker_ip,
                                username=brute_force_credentials["username"],
                                password=brute_force_credentials["password"]
                            )

                if sniffed_topics:
                    print(f"{Fore.GREEN}[+] Hasil Topik MQTT yang di-sniffing:{Style.RESET_ALL}")
                    for topic in sniffed_topics:
                        print(f" - {topic}")
                else:
                    print(f"{Fore.RED}[-] Tidak ada topik yang di-sniff.{Style.RESET_ALL}")

                do_fuzz = input(f"{Fore.YELLOW}[?] Lakukan MQTT Fuzzing ke {broker_ip}? (y/n): {Style.RESET_ALL}")
                if do_fuzz.lower() == 'y':
                    mqtt_fuzzer.mqtt_fuzz_broker(
                        broker_ip,
                        username=brute_force_credentials["username"],
                        password=brute_force_credentials["password"]
                    )

                do_qos = input(f"{Fore.YELLOW}[?] Lakukan MQTT QoS Delay Test ke {broker_ip}? (y/n): {Style.RESET_ALL}")
                if do_qos.lower() == 'y':
                    qos_summary = qos_tester.mqtt_qos_delay_test(
                        broker_ip,
                        username=brute_force_credentials["username"],
                        password=brute_force_credentials["password"]
                    )
                else:
                    qos_summary = {"0": 0.0, "1": 0.0, "2": 0.0}

                do_flood = input(f"{Fore.YELLOW}[?] Lakukan Subscribe + Publish Flood ke {broker_ip}? (y/n): {Style.RESET_ALL}")
                if do_flood.lower() == 'y':
                    flood_attack.mqtt_subscribe_publish(broker_ip)

                do_report = input(f"{Fore.YELLOW}[?] Buatkan laporan PDF untuk {broker_ip}? (y/n): {Style.RESET_ALL}")
                if do_report.lower() == 'y':
                    report_generator.generate_pdf_report(
                        broker_ip=broker_ip,
                        username=brute_force_credentials["username"],
                        password=brute_force_credentials["password"],
                        topics=sniffed_topics,
                        fuzz_count=20,
                        flood_info={"topic_count": "1000", "messages_per_topic": "3000"},
                        qos_delay_summary=qos_summary
                    )
        else:
            print(f"{Fore.RED}[-] Tidak ada broker MQTT ditemukan di jaringan.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] Pilihan tidak valid.{Style.RESET_ALL}")
