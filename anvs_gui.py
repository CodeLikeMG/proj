import sys
import requests
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QTableWidget, QTableWidgetItem
from PyQt6.QtGui import QFont, QColor, QPalette
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from network_scan import scan_network
from service_analysis import analyze_network
from cve_lookup import get_cve_data_mitre
from generate_report import generate_report

class ScannerWorker(QThread):
    update_console = pyqtSignal(str)
    update_results = pyqtSignal(list)
    scan_complete = pyqtSignal()

    def run(self):
        self.update_console.emit("\n[+] Scanning Network...")

        # Perform Network Scan
        network_results = scan_network("192.168.0.0/256", fast_scan=True)
        self.update_console.emit(f"[✔] Network Scan Completed. {len(network_results)} hosts found.")

        # Analyze Network Traffic
        self.update_console.emit("\n[+] Capturing Network Packets...")
        detected_services = analyze_network()
        self.update_console.emit(f"[✔] Detected {len(detected_services)} services.")

        # Fetch CVE Data
        self.update_console.emit("\n[+] Checking for Vulnerabilities...")
        scan_results = []

        for service in detected_services:
            service_name = service.get("Service", "Unknown").lower().strip()
            if service_name == "unknown" or service_name == "":
                self.update_console.emit(f"⚠️ Skipping unknown service on port {service.get('Port', 'N/A')}")
                continue  # Skip unknown services

            self.update_console.emit(f"🔍 Checking {service_name} for vulnerabilities...")

            vulnerabilities = get_cve_data_mitre(service_name)

            if vulnerabilities is None:  # Prevents 'NoneType' iteration error
                self.update_console.emit(f"❌ No CVE data found for {service_name}. Skipping...")
                continue

            if isinstance(vulnerabilities, dict):  # If a single CVE is returned
                vulnerabilities = [vulnerabilities]

            for vuln in vulnerabilities:
                scan_results.append([
                    service.get("IP", "Unknown"),
                    str(service.get("Port", "Unknown")),
                    service_name,
                    vuln.get("CVE", "Unknown")
                ])

        self.update_console.emit("[✔] Scan Complete!")
        self.update_results.emit(scan_results)
        self.scan_complete.emit()

class VulnerabilityScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Automated Network Vulnerability Scanner")
        self.setGeometry(300, 100, 900, 600)
        
        # Dark Theme
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(20, 20, 20))
        palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.green)
        self.setPalette(palette)
        
        layout = QVBoxLayout()
        
        # Title
        self.label = QLabel("🔍 Automated Network Vulnerability Scanner", self)
        self.label.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.label)
        
        # Start Scan Button
        self.scan_button = QPushButton("Start Scan", self)
        self.scan_button.setFont(QFont("Consolas", 12))
        self.scan_button.setStyleSheet("background-color: #444; color: green;")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)
        
        # Output Console
        self.output_console = QTextEdit(self)
        self.output_console.setFont(QFont("Consolas", 10))
        self.output_console.setStyleSheet("background-color: black; color: green;")
        self.output_console.setReadOnly(True)
        layout.addWidget(self.output_console)
        
        # Results Table
        self.results_table = QTableWidget(self)
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["IP", "Port", "Service", "Vulnerability"])
        layout.addWidget(self.results_table)
        
        self.setLayout(layout)
    
    def start_scan(self):
        self.output_console.append("\n🚀 Starting Scan...")
        self.scan_button.setEnabled(False)  # Disable button during scan

        self.scanner_thread = ScannerWorker()
        self.scanner_thread.update_console.connect(self.output_console.append)
        self.scanner_thread.update_results.connect(self.update_results_table)
        self.scanner_thread.scan_complete.connect(self.on_scan_complete)
        self.scanner_thread.start()

    def on_scan_complete(self):
        self.scan_button.setEnabled(True)
        self.output_console.append("[✔] Scan Completed! Generating Report...")

        # Collect data from table for report
        report_data = []
        for row in range(self.results_table.rowCount()):
            report_data.append({
                "IP": self.results_table.item(row, 0).text(),
                "Port": self.results_table.item(row, 1).text(),
                "Service": self.results_table.item(row, 2).text(),
                "CVE": self.results_table.item(row, 3).text()
            })

        # Generate Report
        generate_report(report_data)
        self.output_console.append("[✔] Report successfully generated: report.pdf")
    
    def update_results_table(self, results):
        self.results_table.setRowCount(0)  # Clear previous results
        for row in results:
            row_pos = self.results_table.rowCount()
            self.results_table.insertRow(row_pos)
            for col, data in enumerate(row):
                self.results_table.setItem(row_pos, col, QTableWidgetItem(data))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = VulnerabilityScannerGUI()
    gui.show()
    sys.exit(app.exec())
