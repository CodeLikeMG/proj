# Automated Network Vulnerability Scanner with DevOps Integration

## Project Overview
This project is an Automated Network Vulnerability Scanner designed to identify security vulnerabilities in network services using continuous and automated scanning techniques aligned with DevOps principles. It integrates network scanning, service analysis, vulnerability detection via CVE lookups from the MITRE database, and automated report generation. The project features a user-friendly PyQt6 GUI for ease of use and real-time feedback.

## Key Features
- Automated network scanning using nmap with fast and full scan modes.
- Live network traffic analysis to detect running services.
- CVE vulnerability lookup using MITRE API for known services.
- Automated PDF report generation summarizing vulnerabilities.
- PyQt6 GUI for interactive scanning and results visualization.
- Emphasis on automation and continuous monitoring, reflecting DevOps and DevSecOps practices.

## DevOps and Cybersecurity Integration
- **Automation:** The entire scanning and reporting process is automated, reducing manual intervention.
- **Continuous Monitoring:** The tool can be integrated into CI/CD pipelines or scheduled tasks for continuous security assessment.
- **Integration:** The modular design allows integration with other DevOps tools and workflows.
- **Security Focus:** By identifying vulnerabilities early, it supports the DevSecOps goal of shifting security left in the development lifecycle.

## Setup Instructions
1. Clone or download the project folder.
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Verify installation:
   ```
   python -c "import PyQt6, scapy.all, nmap, fpdf, requests; print('All dependencies installed successfully!')"
   ```
4. Run the GUI scanner:
   ```
   python anvs_gui.py
   ```

## Usage
- Click the "Start Scan" button in the GUI to begin scanning the network.
- View real-time scan progress and detected vulnerabilities.
- After the scan completes, a detailed PDF report will be generated automatically.

## Potential Enhancements
- Integration with CI/CD pipelines for automated scans on code or infrastructure changes.
- Containerization using Docker for easy deployment and scalability.
- Alerting and notification system for critical vulnerabilities.
- Extended CVE database support and real-time updates.

## Conclusion
This project demonstrates a practical application of DevOps principles in cybersecurity, making it an excellent choice for a college major project.
