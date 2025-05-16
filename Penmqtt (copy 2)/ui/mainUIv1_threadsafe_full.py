import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.controller import PenTestController
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QPushButton, QLineEdit, QFrame, QTableWidget, 
                             QTableWidgetItem, QScrollArea, QTextEdit, QStackedWidget,
                             QMessageBox, QDialog, QGroupBox, QCheckBox, QComboBox)
from PySide6.QtCore import Qt, QSize, QEvent
from PySide6.QtCore import QMetaObject, Qt, Q_ARG

def safe_set_label_text(label, text):
    QMetaObject.invokeMethod(label, "setText", Qt.QueuedConnection, Q_ARG(str, text))

def safe_append_text(textedit, text):
    def append():
        textedit.append(text)
        textedit.verticalScrollBar().setValue(textedit.verticalScrollBar().maximum())
    QMetaObject.invokeMethod(textedit, "append", Qt.QueuedConnection, Q_ARG(str, text))

from PySide6.QtGui import QFont, QColor
import threading
from wifiget import get_network_name

from core.controller import PenTestController
from core.sniffer import Sniffer
from core.network_scanner import NetworkScanner
from core.brute_force import BruteForcer
from core.dos_flodder import DoSFlooder
from core.mqtt_enum import MQTTEnumerator
from core.fuzzer import Fuzzer
from core.qos_delay import QoSTester
from core.report import ReportGenerator

class PenMQTT(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PenMQTT")
        self.resize(1920, 1080)  # Set window size to 1920x1080
        self.setStyleSheet("""
            QMainWindow {
                background-color: #a0a0a0;
            }
            QLabel {
                font-size: 14px;
                color: black;
            }
            QPushButton {
                background-color: white;
                border-radius: 5px;
                padding: 5px;
                font-size: 14px;
                color: black;
            }
            QPushButton#scanButton {
                background-color: #ffff70;
                font-weight: bold;
                color: black;
            }
            QPushButton#enterButton {
                background-color: #90ee90;
                color: black;
            }
            QPushButton#reportButton {
                background-color: #87CEFA;
                border-radius: 5px;
                color: black;
            }
            QLineEdit {
                border: 1px solid gray;
                border-radius: 5px;
                padding: 2px;
                color: black;
            }
            QFrame#section {
                background-color: white;
                border-radius: 10px;
                padding: 10px;
            }
            QFrame#statusSection {
                background-color: #e74c3c;
                border-radius: 10px;
                padding: 10px;
            }
            QTableWidget {
                background-color: white;
                gridline-color: gray;
                color: black;
            }
            QTableWidget::item:selected {
                background-color: #87CEFA;
            }
            QScrollArea {
                border: none;
            }
            QTextEdit {
                color: black;
            }
            QPushButton#testReportButton {
            background-color: #FF7F50;
            border-radius: 5px;
            color: white;
            font-weight: bold;
            padding: 5px 10px;
        }
        """)
        
        # Initialize NetworkScanner
        self.network_scanner = NetworkScanner()
        
        # Initialize device tracking
        self.device_buttons = []
        self.current_device = None

        # Central widget
        central_widget = QWidget()
        main_layout = QHBoxLayout(central_widget)
        
        # Left side (Section 1)
        left_layout = QVBoxLayout()
        
        # Logo
        logo_layout = QHBoxLayout()
        logo_label = QLabel("PenMQTT")
        logo_label.setStyleSheet("font-size: 24px; font-weight: bold; background-color: #e0e0e0; border-radius: 20px; padding: 10px; color: black;")
        logo_layout.addWidget(logo_label)
        logo_layout.addStretch()
        left_layout.addLayout(logo_layout)
        
        # Section 1: Network scanning section
        section1 = QFrame()
        section1.setObjectName("section")
        section1_layout = QVBoxLayout(section1)
        
        # Network selection
        network_layout = QHBoxLayout()
        network_label = QLabel("Network :")
        self.network_value = QLabel(get_network_name())
        self.network_value.setStyleSheet("border: 1px solid black; border-radius: 10px; padding: 5px; color: black;")
        network_layout.addWidget(network_label)
        network_layout.addWidget(self.network_value)
        section1_layout.addLayout(network_layout)
        
        # Scan button
        scan_button = QPushButton("Scan")
        scan_button.setObjectName("scanButton")
        scan_button.setMinimumHeight(50)
        section1_layout.addWidget(scan_button)
        
        # Devices label
        devices_label = QLabel("Devices :")
        section1_layout.addWidget(devices_label)
        
        # Devices list container
        self.devices_frame = QFrame()
        self.devices_frame.setFrameShape(QFrame.StyledPanel)
        self.devices_layout = QVBoxLayout(self.devices_frame)
        
        # Add a scroll area for devices
        devices_scroll = QScrollArea()
        devices_scroll.setWidgetResizable(True)
        devices_scroll.setWidget(self.devices_frame)
        section1_layout.addWidget(devices_scroll)
        
        # Credential info section
        cred_frame = QFrame()
        cred_frame.setFrameShape(QFrame.StyledPanel)
        cred_layout = QVBoxLayout(cred_frame)
        
        cred_title = QLabel("Credential Info")
        cred_title.setStyleSheet("color: black;")
        cred_layout.addWidget(cred_title)
        
        id_layout = QHBoxLayout()
        id_label = QLabel("ID / Username :")
        id_label.setStyleSheet("color: black;")
        id_layout.addWidget(id_label)
        cred_layout.addLayout(id_layout)
        
        self.id_input = QLineEdit()
        self.id_input.setPlaceholderText("Enter ID")
        self.id_input.setStyleSheet("color: white;")
        cred_layout.addWidget(self.id_input)
        
        pass_label = QLabel("Password :")
        pass_label.setStyleSheet("color: black;")
        cred_layout.addWidget(pass_label)
        
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Enter Password")
        self.pass_input.setEchoMode(QLineEdit.Password)
        self.pass_input.setStyleSheet("color: white;")
        cred_layout.addWidget(self.pass_input)
        
        enter_layout = QHBoxLayout()
        enter_layout.addStretch()
        enter_button = QPushButton("Enter")
        enter_button.setObjectName("enterButton")
        enter_layout.addWidget(enter_button)
        cred_layout.addLayout(enter_layout)
        
        section1_layout.addWidget(cred_frame)
        
        left_layout.addWidget(section1)
        main_layout.addLayout(left_layout, 1)
        
        # Right side (Sections 2, 3, and 4)
        right_layout = QVBoxLayout()
        
        # Section 2: Status bar
        section2 = QFrame()
        section2.setObjectName("statusSection")
        section2_layout = QVBoxLayout(section2)

        status_title_label = QLabel("Status")
        status_title_label.setAlignment(Qt.AlignCenter)
        status_title_label.setStyleSheet("color: white; font-size: 16px; font-weight: bold;")
        section2_layout.addWidget(status_title_label)

        # Status indicators in a row
        status_indicators_layout = QHBoxLayout()
        self.status_types = ["BruteForce", "Sniffing", "Fuzzing", "DoS"]
        self.status_indicators = {}

        for status_type in self.status_types: 
            # Create a frame for each status indicator
            indicator_frame = QFrame()
            indicator_frame.setStyleSheet("""
                QFrame {
                    background-color: white;
                    border-radius: 8px;
                    border: none;
                }
            """)
            
            # Create a layout for the indicator
            indicator_layout = QVBoxLayout(indicator_frame)
            indicator_layout.setContentsMargins(5, 5, 5, 5)
            
            # Create status label
            status_label = QLabel(status_type)
            status_label.setStyleSheet("color: black; font-size: 16px;")
            status_label.setAlignment(Qt.AlignCenter)
            indicator_layout.addWidget(status_label)
            
            
            # Store the indicator frame reference
            self.status_indicators[status_type] = indicator_frame
            
            # Add to layout
            status_indicators_layout.addWidget(indicator_frame)

        section2_layout.addLayout(status_indicators_layout)

        right_layout.addWidget(section2)

        
        # Section 3: Report view
        section3 = QFrame()
        section3.setObjectName("section")
        section3_layout = QVBoxLayout(section3)
        
        self.report_stack = QStackedWidget()
        
        # Empty state
        empty_widget = QWidget()
        empty_layout = QVBoxLayout(empty_widget)
        empty_label = QLabel("Select a device to view details")
        empty_label.setAlignment(Qt.AlignCenter)
        empty_layout.addWidget(empty_label)
        self.report_stack.addWidget(empty_widget)
        
        # Report content state
        self.report_widget = QWidget()
        report_content_layout = QVBoxLayout(self.report_widget)
        
        report_header_layout = QHBoxLayout()
        self.device_info_label = QLabel("No device selected")
        self.device_info_label.setStyleSheet("color: black;")
        report_header_layout.addWidget(self.device_info_label)
        report_header_layout.addStretch()
        
        self.status_info = QLabel("")
        self.status_info.setStyleSheet("color: black;")
        report_header_layout.addWidget(self.status_info)
        
        generate_report = QPushButton("Generate Report")
        generate_report.setObjectName("reportButton")
        generate_report.clicked.connect(self.generate_report)
        report_header_layout.addWidget(generate_report)

        auto_test_button = QPushButton("Run Full Pentest")
        auto_test_button.setObjectName("testReportButton")
        auto_test_button.clicked.connect(self.run_full_pentest_ui)
        report_header_layout.addWidget(auto_test_button)

        report_content_layout.addLayout(report_header_layout)
        
        self.attack_type_label = QLabel("")
        self.attack_type_label.setStyleSheet("color: black;")
        report_content_layout.addWidget(self.attack_type_label)
        
        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        self.report_text.setStyleSheet("color: black;")
        report_content_layout.addWidget(self.report_text)
        
        self.report_stack.addWidget(self.report_widget)
        self.report_stack.setCurrentIndex(0)  # Start with empty state
        
        section3_layout.addWidget(self.report_stack)
        right_layout.addWidget(section3, 4)
        
        # Section 4: Audit log
        section4 = QFrame()
        section4.setObjectName("section")
        section4_layout = QVBoxLayout(section4)

        
        self.log_table = QTableWidget(0, 5)  # Start with 0 rows, 5 columns
        self.log_table.setHorizontalHeaderLabels(["Device Name", "TimeStamp", "Subject", "Description", "Status"])
        self.log_table.horizontalHeader().setStyleSheet("color: white;")

        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)  # Disable editing
        
        # Set column widths
        self.log_table.setColumnWidth(0, 150)  # Increased width
        self.log_table.setColumnWidth(1, 200)  # Increased width
        self.log_table.setColumnWidth(2, 150)  # Increased width
        self.log_table.setColumnWidth(3, 400)  # Increased width
        self.log_table.setColumnWidth(4, 100)  # Increased width

        # Make the table take more space
        section4_layout.addWidget(self.log_table)
        right_layout.addWidget(section4, 3)  # Increased stretch factor to 3
        
        main_layout.addLayout(right_layout, 3)
        
        self.setCentralWidget(central_widget)
        
        # Connect signals
        scan_button.clicked.connect(self.scan_network)
        enter_button.clicked.connect(self.enter_credentials)
        
    def scan_network(self):
        """Start a network scan"""
        # Update network info
        # self.network_value.setText("Scanning...")
        
        # Clear existing device buttons
        self.clear_devices_list()
        
        # Show scanning message with a specific object name so we can find it later
        scanning_label = QLabel("Scanning network...")
        scanning_label.setObjectName("scanningLabel")
        scanning_label.setStyleSheet("color: white;")
        self.devices_layout.addWidget(scanning_label)
        QApplication.processEvents()  # Force UI update
        
        # Start network scan in a separate thread to keep UI responsive
        thread = threading.Thread(target=self._run_scan, daemon=True)
        thread.start()

    def _run_scan(self):
        """Run network scan in background thread"""
        try:
            # Perform the scan
            success = self.network_scanner.scan_network()
            if not success:
                # Use signal or other thread-safe method to show error
                print("A scan is already in progress.")
            else:
                # After successful scan, make sure to force update the devices list
                # by getting any cached devices from the network_scanner
                if hasattr(self.network_scanner, 'found_devices'):
                    # Update UI on the main thread 
                    QApplication.instance().postEvent(self, QEvent(QEvent.Type.User))
        except Exception as e:
            print(f"Error in network scan: {e}")

    def event(self, event):
        """Handle custom events"""
        if event.type() == QEvent.Type.User:
            # Update devices list from any cached devices
            if hasattr(self.network_scanner, 'found_devices'):
                self.update_devices_list(self.network_scanner.found_devices)
            return True
        return super().event(event)
            
    def clear_devices_list(self):
        """Clear the devices list"""
        # Remove the scanning label if it exists
        scanning_label = self.findChild(QLabel, "scanningLabel")
        if scanning_label:
            scanning_label.deleteLater()
        
        # Remove all device buttons
        if hasattr(self, 'device_buttons'):
            for button in self.device_buttons:
                button.deleteLater()
            self.device_buttons = []
        
        # Clear any other widgets in the devices layout
        while self.devices_layout.count():
            item = self.devices_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def update_devices_list(self, devices):
        """Update the devices list with scan results"""
        # This is called by the network scanner when scan completes
        self.clear_devices_list()
        
        # Update network name
        try:
            network_name = get_network_name()
            self.network_value.setText(network_name if network_name else "Unknown Network")
        except Exception as e:
            print(f"Error updating network name: {e}")
            self.network_value.setText("Unknown Network")
        
        if not devices:
            no_devices = QLabel("No devices found")
            no_devices.setStyleSheet("color: black;")
            self.devices_layout.addWidget(no_devices)
            return
        
        # Add device buttons with proper connection to handle selection
        for device in devices:
            device_text = f"{device['name']} ({device['ip']})"
            device_button = QPushButton(device_text)
            device_button.setStyleSheet("""
                QPushButton {
                    text-align: left;
                    color: black;
                    padding: 8px;
                    border: 1px solid #d0d0d0;
                    border-radius: 4px;
                    margin: 2px;
                }
                QPushButton:hover {
                    background-color: #e0e0e0;
                }
            """)
            
            # Use a lambda with default argument to avoid late binding issues
            device_button.clicked.connect(lambda checked, d=device: self.select_device(d))
            
            self.devices_layout.addWidget(device_button)
            self.device_buttons.append(device_button)
        
        # Add stretch to push buttons to top
        self.devices_layout.addStretch()
        
        # Add log entry
        self.add_log_entry("N/A", "Information", f"Network scan completed. Found {len(devices)} devices.", "Succeed")
        
        # Force UI update
        QApplication.processEvents()
        
    def select_device(self, device):
        self.current_device = device
        self.device_info_label.setText(f"{device['name']} ({device['ip']}) - {device['mac']}")
        safe_set_label_text(self.status_info, "Scanning...")
        self.attack_type_label.setText("Device Information")
        self.report_text.setText("Gathering detailed information about this device...")
        self.report_stack.setCurrentIndex(1)

        self.network_scanner.get_device_details(device['ip'], callback=self.update_device_details)
        self.add_log_entry(device['name'], "Information", f"Device selected: {device['ip']}", "Succeed")

        # Jalankan pentest otomatis (bertahap) setelah klik IP
        thread = threading.Thread(
            target=self.run_sequential_pentest,
            args=(device['ip'], device['name']),
            daemon=True
        )
        thread.start()


    def append_to_report_text(self, message):
        safe_append_text(self.report_text, str(message))
        self.report_text.verticalScrollBar().setValue(
            self.report_text.verticalScrollBar().maximum()
        )
        QApplication.processEvents()

    def run_sequential_pentest(self, ip, device_name):
        try:
            self.controller = PenTestController(logger=self.append_to_report_text)
            self._update_attack_report("Menjalankan pentest bertahap...\n")
            safe_set_label_text(self.status_info, "Running...")

            self._update_attack_report("➤ Sniffing broker...\n")
            scanner = NetworkScanner()
            interface = scanner.interface
            sniffer = sniffer(interface)
            broker_list = sniffer.sniff_broker_from_iot(ip)
            if not broker_list:
                self._update_attack_report("[!] Broker MQTT tidak ditemukan.\n")
                return
            broker_ip = broker_list[0]

            self._update_attack_report(f"[✓] Broker ditemukan: {broker_ip}\n")
            self.controller.broker_ip = broker_ip

            self._update_attack_report("➤ Enumerasi topic...\n")
            enum = MQTTEnumerator(logger=self.append_to_report_text)
            topics = enum.enum(broker_ip)
            if not topics:
                self._update_attack_report("➤ Jalankan brute force...\n")
                bruter = BruteForcer(logger=self.append_to_report_text)
                creds = bruter.brute_force(broker_ip)
                if creds:
                    self.controller.credentials = creds
                    self._update_attack_report(f"[✓] Kredensial ditemukan: {creds[0]}:{creds[1]}\n")
                    topics = enum.enum(broker_ip, creds[0], creds[1])
                else:
                    self._update_attack_report("[!] Gagal brute force.\n")
            self.controller.topics = topics

            self._update_attack_report("➤ Jalankan Fuzzing...\n")
            fuzzer = Fuzzer(broker_ip, *self.controller.credentials, logger=self.append_to_report_text)
            fuzzer.run(topics)

            self._update_attack_report("➤ Uji Delay QoS...\n")
            qos = QoSTester(broker_ip, *self.controller.credentials, logger=self.append_to_report_text)
            qos_summary = qos.run()
            self.controller.qos_summary = qos_summary

            self._update_attack_report("➤ Jalankan Subscribe Flood (DoS)...\n")
            dos = DoSFlooder(broker_ip, *self.controller.credentials, logger=self.append_to_report_text)
            dos.run()

            self._update_attack_report("➤ Membuat laporan...\n")
            report = ReportGenerator(f"report_{broker_ip.replace('.', '_')}.pdf", logger=self.append_to_report_text)
            report.generate(
                broker_ip=broker_ip,
                username=self.controller.credentials[0],
                password=self.controller.credentials[1],
                topics=topics,
                fuzz_count=20,
                flood_info={"topic_count": "1000", "messages_per_topic": "3000"},
                qos_delay_summary=qos_summary
            )

            safe_set_label_text(self.status_info, "Succeed")
            self._update_attack_report("[✓] Pentest selesai. Laporan telah dibuat.\n")

            self.add_log_entry(device_name, "Pentest", f"Pentest selesai untuk {ip}", "Succeed")

        except Exception as e:
            self._update_attack_report(f"[ERROR] {str(e)}")


    
    def update_device_details(self, details):
        if not details:
            self.report_text.setText("Error fetching device details.")
            safe_set_label_text(self.status_info, "Failed")
            return
        
        # Format and display device details
        text = f"""
        Device IP: {details['ip']}
        MAC Address: {details['mac']}
        Vendor: {details['vendor']}
        Operating System: {details['os']}

        Open Ports:
        """
        
        if details['ports']:
            for port in details['ports']:
                text += f"• {port['number']}/{port['protocol']} - {port['state']} - {port['service']}"
                if port['product']:
                    text += f" ({port['product']}"
                    if port['version']:
                        text += f" {port['version']}"
                    text += ")"
                text += "\n"
        else:
            text += "No open ports detected."
        
        self.report_text.setText(text)
        safe_set_label_text(self.status_info, "Succeed")
        
        # Add log entry
        self.add_log_entry(self.current_device['name'], "Device Info", f"Scanned {details['ip']}", "Succeed")
    
    def update_status_indicator(self, status_type, active=False):
        """Update the status indicator for a given module"""
        if status_type in self.status_indicators:
            if active:
                # Active state - green background
                self.status_indicators[status_type].setStyleSheet("""
                    QFrame {
                        background-color: #FFFF00; 
                        border-radius: 8px;
                        border: none;
                    }
                """)
            else:
                # Inactive state - dark gray background
                self.status_indicators[status_type].setStyleSheet("""
                    QFrame {
                        background-color: white; 
                        border-radius: 8px;
                        border: none;
                    }
                """)

    def start_automated_status_cycle(self):
        """Start automated status cycling from left to right"""
        # Initialize cycle index
        self.current_status_index = -1
        self.automated_status_running = True
        
        # Create a QTimer for automated cycling
        from PySide6.QtCore import QTimer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.cycle_next_status)
        self.status_timer.start(1000)  # Update every 1 second
        
        # Add log entry
        self.add_log_entry("System", "Information", "Automated scanning started", "Running")

# Modify the cycle_next_status method to stop after one complete iteration

    def cycle_next_status(self):
        """Cycle to the next status in the sequence"""
        if not hasattr(self, 'automated_status_running') or not self.automated_status_running:
            return
            
        # Reset all indicators to inactive first
        for status_type in self.status_types:
            self.update_status_indicator(status_type, False)
        
        # Move to next index
        self.current_status_index = (self.current_status_index + 1) % len(self.status_types)
        current_status = self.status_types[self.current_status_index]
        
        # Update status indicator and display
        self.update_status_indicator(current_status, True)
        
        # Update report text if a device is selected
        if hasattr(self, 'current_device') and self.current_device is not None:
            self.attack_type_label.setText(current_status)
            safe_set_label_text(self.status_info, "Running...")
            safe_append_text(self.report_text, f"Running {current_status} scan...\n")
            
            # Add some simulated output based on the status type
            if current_status == "BruteForce":
                safe_append_text(self.report_text, "Testing common credentials...\n")
            elif current_status == "DoS":
                safe_append_text(self.report_text, "Testing response under load...\n")
            elif current_status == "Sniffing":
                safe_append_text(self.report_text, "Capturing network traffic...\n")
            elif current_status == "Fuzzing":
                safe_append_text(self.report_text, "Testing input validation...\n")
            
            # Scroll to bottom
            self.report_text.verticalScrollBar().setValue(
                self.report_text.verticalScrollBar().maximum()
            )
        
        # Add log entry for the current status
        if hasattr(self, 'current_device') and self.current_device is not None:
            self.add_log_entry(
                self.current_device['name'], 
                current_status, 
                f"Automated {current_status} scan", 
                "Running"
            )
        else:
            self.add_log_entry(
                "N/A", 
                current_status, 
                "Automated scanning", 
                "Running"
            )
        
        # Check if we've completed one full iteration (back to the first status type)
        if self.current_status_index == len(self.status_types) - 1:
            # Stop the timer after one full cycle
            self.stop_automated_status_cycle()
            
            # Log that the cycle is complete
            self.add_log_entry(
                "System", 
                "Information", 
                "Automated scanning cycle completed", 
                "Completed"
            )

    def stop_automated_status_cycle(self):
        """Stop the automated status cycling"""
        if hasattr(self, 'status_timer'):
            self.status_timer.stop()
        
        self.automated_status_running = False
        
        # Reset all indicators
        for status_type in self.status_types:
            self.update_status_indicator(status_type, False)
        
        # Add log entry
        self.add_log_entry("System", "Information", "Automated scanning stopped", "-")

    def run_attack(self, attack_type):
        # Reset all indicators first
        for status_type in self.status_types:
            self.update_status_indicator(status_type, False)

        # Activate only the current attack indicator
        self.update_status_indicator(attack_type, True)
        if not hasattr(self, 'current_device') or self.current_device is None:
            QMessageBox.warning(self, "No Device Selected", "Please select a device first.")
            return
    
        # Update UI
        self.attack_type_label.setText(attack_type)
        safe_set_label_text(self.status_info, "Running...")
        
        # Clear existing report
        self.report_text.clear()
        safe_append_text(self.report_text, f"Running {attack_type} attack on {self.current_device['ip']}...\n\n")
        
        # Get credentials if entered
        username = self.id_input.text() if self.id_input.text() != "DeviceID" else None
        password = self.pass_input.text() if self.pass_input.text() != "Pass123" else None
        
        # For now, we'll just add a placeholder message
        # This will be replaced with actual implementations for each attack type later
        self._update_attack_report(f"Simulating {attack_type} attack. Actual functionality will be implemented later.")
        safe_set_label_text(self.status_info, "Succeed")
        
        # Add log entry
        self.add_log_entry(
            self.current_device['name'], 
            attack_type, 
            f"Executed {attack_type} on {self.current_device['ip']}", 
            "Succeed"
        )
        
    def _update_attack_report(self, message):
        """Update the attack report with a new message"""
        safe_append_text(self.report_text, message)
        # Scroll to the bottom
        self.report_text.verticalScrollBar().setValue(
            self.report_text.verticalScrollBar().maximum()
        )
        # Process events to update UI
        QApplication.processEvents()

    def generate_report(self):
        if not hasattr(self, 'current_device') or self.current_device is None:
            QMessageBox.warning(self, "No Device Selected", "Please select a device first.")
            return
        
        # Create and show the report generation dialog
        dialog = ReportGenerationDialog(self)
        
        # If a device is selected, pre-fill the report name
        if hasattr(self, 'current_device') and self.current_device is not None:
            device_name = self.current_device.get('name', 'Unknown')
            dialog.name_input.setText(f"PenMQTT_Report_{device_name}")
        
        # Show the dialog and wait for user input
        result = dialog.exec()
        
        if result == QDialog.Accepted:
            # Get the report details
            report_name = dialog.name_input.text()
            report_location = dialog.location_input.text()
            report_format = dialog.format_combo.currentText()
            
            # Add log entry for report generation
            self.add_log_entry(
                self.current_device['name'],
                "Report",
                f"Generated {report_format} report for {self.current_device['ip']} at {report_location}/{report_name}",
                "Succeed"
            )
            
            QMessageBox.information(self, "Report Generated", 
                                f"Report has been generated and saved as:\n{report_location}/{report_name}")
            
    def run_full_pentest_ui(self):
        if not hasattr(self, 'current_device') or self.current_device is None:
            QMessageBox.warning(self, "No Device Selected", "Please select a device first.")
            return

        self.report_text.clear()
        safe_append_text(self.report_text, "Running full MQTT pentest...\n")
        safe_set_label_text(self.status_info, "Running...")

        # Jalankan di thread supaya UI tidak freeze
        thread = threading.Thread(
            target=self._execute_full_pentest_thread,
            args=(self.current_device['ip'],),
            daemon=True
        )
        thread.start()


    def _execute_full_pentest_thread(self, ip):
        try:
            self.controller = PenTestController(logger=self.append_to_report_text)
            self.controller.run_full_pentest(selected_ip=ip)

            self._update_attack_report("Full pentest selesai.\nLaporan PDF dibuat.\n")
            safe_set_label_text(self.status_info, "Succeed")

            self.add_log_entry(
                self.current_device['name'],
                "Pentest",
                f"Pentest selesai untuk {ip}.",
                "Succeed"
            )
        except Exception as e:
            self._update_attack_report(f"[ERROR] {str(e)}")
            safe_set_label_text(self.status_info, "Failed")

            self.add_log_entry(
                self.current_device['name'],
                "Pentest",
                f"Pentest gagal: {str(e)}",
                "Failed"
            )


    def enter_credentials(self):
        if not hasattr(self, 'current_device') or self.current_device is None:
            QMessageBox.warning(self, "No Device Selected", "Please select a device first.")
            return
            
        username = self.id_input.text()
        password = self.pass_input.text()
        
        # Add log entry
        self.add_log_entry(
            self.current_device['name'],
            "Credentials",
            f"Entered credentials for {self.current_device['ip']}",
            "Succeed"
        )
        
        QMessageBox.information(self, "Credentials Entered", 
                               f"Credentials entered for {self.current_device['name']}:\nUsername: {username}")
    
    def add_log_entry(self, device, subject, description, status):
        from datetime import datetime
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%m/%d/%Y %H:%M")
        
        # Add new row to log table
        row_position = self.log_table.rowCount()
        self.log_table.insertRow(row_position)
        
        # Set table items
        device_item = QTableWidgetItem(device)
        device_item.setForeground(QColor("black"))
        self.log_table.setItem(row_position, 0, device_item)
        
        timestamp_item = QTableWidgetItem(timestamp)
        timestamp_item.setForeground(QColor("black"))
        self.log_table.setItem(row_position, 1, timestamp_item)
        
        subject_item = QTableWidgetItem(subject)
        subject_item.setForeground(QColor("black"))
        self.log_table.setItem(row_position, 2, subject_item)
        
        desc_item = QTableWidgetItem(description)
        desc_item.setForeground(QColor("black"))
        self.log_table.setItem(row_position, 3, desc_item)
        
        status_item = QTableWidgetItem(status)
        if status == "Succeed":
            status_item.setForeground(QColor("#FF6347"))  # Red text for "Succeed"
        else:
            status_item.setForeground(QColor("black"))
        self.log_table.setItem(row_position, 4, status_item)
        
        # Scroll to the newest entry
        self.log_table.scrollToBottom()

class ReportGenerationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generate Report")
        self.setMinimumWidth(500)
        self.setStyleSheet("""
            QDialog {
                background-color: #f0f0f0;
            }
            QLabel {
                font-size: 14px;
                color: black;
            }
            QPushButton {
                background-color: white;
                border-radius: 5px;
                padding: 5px;
                font-size: 14px;
                color: black;
            }
            QPushButton#saveButton {
                background-color: #90ee90;
                color: black;
            }
            QPushButton#cancelButton {
                background-color: #f0f0f0;
                color: black;
            }
            QLineEdit {
                border: 1px solid gray;
                border-radius: 5px;
                padding: 4px;
                color: black;
            }
        
        """)
        
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Report name section
        name_layout = QHBoxLayout()
        name_label = QLabel("Report Name:")
        self.name_input = QLineEdit("PenMQTT_Report")
        name_layout.addWidget(name_label)
        name_layout.addWidget(self.name_input)
        layout.addLayout(name_layout)
        
        # Report location section
        location_layout = QHBoxLayout()
        location_label = QLabel("Location:")
        self.location_input = QLineEdit("/home/user/documents")
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_location)
        location_layout.addWidget(location_label)
        location_layout.addWidget(self.location_input)
        location_layout.addWidget(browse_button)
        layout.addLayout(location_layout)
        
        # Report format section - just a label showing PDF format
        format_layout = QHBoxLayout()
        format_label = QLabel("Format:")
        format_value = QLabel("PDF (.pdf)")
        # Store the format value for reference when saving
        self.format_combo = QLabel("PDF (.pdf)")
        self.format_combo.setVisible(False)  # Hide but keep for compatibility
        format_layout.addWidget(format_label)
        format_layout.addWidget(format_value)
        layout.addLayout(format_layout)
        
        # Buttons section
        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        
        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("cancelButton")
        cancel_button.clicked.connect(self.reject)
        
        save_button = QPushButton("Save Report")
        save_button.setObjectName("saveButton")
        save_button.clicked.connect(self.accept)
        
        buttons_layout.addWidget(cancel_button)
        buttons_layout.addWidget(save_button)
        layout.addLayout(buttons_layout)
    
    def browse_location(self):
        # This would open a file dialog to select directory
        # We'll just simulate it for now
        pass

def main():
    app = QApplication(sys.argv)
    window = PenMQTT()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()