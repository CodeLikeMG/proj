import pandas as pd 
from network_scan import scan_network
from service_analysis import analyze_network
from cve_lookup import get_cve_data_mitre
#from cve_lookup import get_cve_data
from generate_report import generate_report

def main():
    print("🚀 Starting Automated Network Vulnerability Scanner...")

    # Step 1: Perform Network Scan (One-time execution, Fast Mode Enabled)
    network_data = scan_network("192.168.0.0/256", fast_scan=True)
    print("📡 Network Scan Results:", network_data)

    # Step 2: Analyze Services (Live Packet Capture)
    service_data = analyze_network()
    print("🔍 Detected Services from Network Traffic:", service_data)

    # Step 3: Match Unidentified Services with Nmap Data
    for service in service_data:
        if service["Service"] == "Unknown":
            for nmap_entry in network_data:
                if nmap_entry["Port"] == service["Port"]:
                    service["Service"] = nmap_entry["Service"]
                    service["Version"] = nmap_entry["Version"]
                    print(f"🛠️ Matched Unknown Service on Port {service['Port']} to: {service['Service']} ({service['Version']})")

    print("🔍 Services to be checked for vulnerabilities:", service_data)


    # Step 4: Check for CVEs Only for Identified Services
    cve_data = []
    for service in service_data:
            vulnerabilities = get_cve_data_mitre(service["Service"].lower())  # Replace with real CVE ID if needed
            if vulnerabilities is None:
             continue
            if isinstance(vulnerabilities, dict):  # If a single CVE is returned
                vulnerabilities = [vulnerabilities]  # Convert to list format

            for vuln in vulnerabilities:
                cve_data.append({
                    "IP": service.get('IP', 'Unknown'),
                    "Port": service.get('Port', 'Unknown'),
                    "Service": service['Service'],
                    "Version": service.get('Version', 'Unknown'),
                    "CVE": vuln.get('CVE', 'Unknown'),
                    "Summary": vuln.get('Summary', 'No description available'),
                    "Severity": vuln.get('Severity', 'N/A')
                })
        
    
    
    # Print Final CVE Lookup Results
    print("🔍 CVE Lookup Results:", cve_data)

    # Step 5: Generate Report if CVEs are Found
    if cve_data:
        generate_report(cve_data)
    else:
        print("⚠️ No vulnerabilities found. Report will not be generated.")

if __name__ == "__main__":
    main()
