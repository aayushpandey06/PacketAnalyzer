import json
import requests
from scapy.all import rdpcap

# Path to the .pcap file
PCAP_FILE = "IP_Addressess.pcap"
# Output JSON file
OUTPUT_JSON = "output.json"

def get_geo_location(ip_address):
    """
    Get geographical location (latitude, longitude, city, country) for an IP address using ip-api.com.
    """
    url = f"http://ip-api.com/json/{ip_address}"
    try:
        response = requests.get(url, timeout=5)
        data = response.json()
        if data["status"] == "success":
            return {
                "ip": ip_address,
                "latitude": data["lat"],
                "longitude": data["lon"],
                "city": data["city"],
                "country": data["country"]
            }
        else:
            return {"ip": ip_address, "error": "Location not found"}
    except Exception as e:
        print(f"Error processing IP {ip_address}: {e}")
        return {"ip": ip_address, "error": str(e)}

def process_pcap(file_path):
    """
    Process the .pcap file and extract unique IP addresses.
    """
    packets = rdpcap(file_path)
    ip_addresses = set()

    for packet in packets:
        if packet.haslayer("IP"):
            ip_src = packet["IP"].src
            ip_dst = packet["IP"].dst
            ip_addresses.add(ip_src)
            ip_addresses.add(ip_dst)

    return list(ip_addresses)

def main():
    # Extract IP addresses from the .pcap file
    ip_addresses = process_pcap(PCAP_FILE)

    # Get geographical locations for each IP address
    geo_locations = []
    for ip in ip_addresses:
        location = get_geo_location(ip)
        geo_locations.append(location)

    # Print the output in a structured format
    print(json.dumps(geo_locations, indent=4))

    # Dump the output to a JSON file
    with open(OUTPUT_JSON, "w") as f:
        json.dump(geo_locations, f, indent=4)

    print(f"Output saved to {OUTPUT_JSON}")

if __name__ == "__main__":
    main()
