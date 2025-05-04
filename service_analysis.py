from scapy.all import sniff, IP, TCP, UDP, Raw

# Service-Port Mapping for Better Detection
SERVICE_PORT_MAPPING = {
    80: ("http", "1.1"),
    443: ("https", "1.3"),
    22: ("ssh", "7.4"),
    3306: ("mysql", "5.7"),
    25: ("smtp", "3.1"),
    587: ("smtp", "3.1"),
    53: ("dns", "9.16"),
    21: ("ftp", "1.0"),
    3389: ("rdp", "10.0"),
    23: ("telnet", "2.0")
}

def extract_service_info(packet):
    """Extracts real-time service information from captured packets."""
    service_data = {}

    if packet.haslayer(IP):
        service_data["IP"] = packet[IP].src

    if packet.haslayer(TCP) and TCP in packet:
        service_data["Protocol"] = "TCP"
        service_data["Port"] = packet[TCP].dport

    elif packet.haslayer(UDP) and UDP in packet:
        service_data["Protocol"] = "UDP"
        service_data["Port"] = packet[UDP].dport

    # Assign service based on known mappings
    port = service_data.get("Port")
    if port in SERVICE_PORT_MAPPING:
        service_data["Service"], service_data["Version"] = SERVICE_PORT_MAPPING[port]
    else:
        service_data["Service"] = "Unknown"
        service_data["Version"] = "N/A"

    return service_data if "Service" in service_data else None

def analyze_network():
    print("📡 Capturing network packets...")
    detected_services = []

    def process_packet(packet):
        service_info = extract_service_info(packet)
        if service_info:
            detected_services.append(service_info)

    sniff(count=50, filter="tcp or udp", prn=process_packet)  # Capture live packets
    return detected_services if detected_services else [{"Service": "No data", "Version": "N/A"}]
