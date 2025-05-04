import requests

# Known CVE mappings for faster lookup
KNOWN_SERVICE_CVES = {
    "apache": "CVE-2021-41773",
    "mysql": "CVE-2020-14885",
    "ssh": "CVE-2023-48795",
    "ftp": "CVE-2019-10149",
    "smtp": "CVE-2021-34523",
    "rdp": "CVE-2022-26809",
    "telnet": "CVE-2020-10188",
    "dns": "CVE-2020-25684"
}

def get_cve_data_mitre(service_name):
    """Fetches CVE details from MITRE API using known service mappings."""
    if service_name not in KNOWN_SERVICE_CVES:
        return None  # Skip invalid services

    cve_id = KNOWN_SERVICE_CVES[service_name]
    base_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    try:
        response = requests.get(base_url)
        response.raise_for_status()
        cve_data = response.json()

        summary = cve_data["containers"]["cna"]["descriptions"][0]["value"]
        severity = cve_data["containers"]["cna"].get("metrics", [{}])[0].get("cvssV3_1", {}).get("baseSeverity", "N/A")

        return {"CVE": cve_id, "Summary": summary, "Severity": severity}

    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching CVE data from MITRE: {e}")
        return None
