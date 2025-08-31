# PacketAnalyzer
Wireshark and Python for Network Traffic Analysis

Problem: Understanding how to detect suspicious outbound connections in real network 
traffic is critical for SOC analysts, since attackers often exfiltrate data or beacon to
command-and-control servers.

Action: I set up Wireshark to capture live traffic from normal user activity (web browsing, VoIP calls). 
I exported the packet capture (PCAP) and wrote a Python script to parse the traffic, extract source/destination
IPs, and map them to geolocations. The script automatically flagged any IPs that had no clear geolocation or resolve
d to unusual regions.

Result: The analysis highlighted several “UNKNOWN” destinations, which would represent potentially 
suspicious traffic in a SOC workflow. From this, I documented an escalation procedure: any IP flagged
as “UNKNOWN” should be correlated with threat intelligence feeds before being dismissed or investigated further.
