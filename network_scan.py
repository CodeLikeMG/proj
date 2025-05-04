import nmap

def scan_network(network_range="192.168.0.0/256", fast_scan=False):
    scanner = nmap.PortScanner()

    # Fast scan mode (only scans top 100 common ports)
    scan_args = "-F" if fast_scan else "-p 1-65535 -T4 -A"

    print(f"🔍 Scanning Network: {network_range} ...")
    scanner.scan(hosts=network_range, arguments=scan_args)

    scan_results = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                scan_results.append({
                    "IP": host,
                    "Port": port,
                    "State": scanner[host][proto][port]['state'],
                    "Service": scanner[host][proto][port].get('name', 'Unknown'),
                    "Version": scanner[host][proto][port].get('version') or "1.0"
                    #"Version": scanner[host][proto][port].get('version', 'Unknown')
                })
    
    print("✅ Network Scan Complete!")
    return scan_results

