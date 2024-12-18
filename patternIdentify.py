from scapy.all import rdpcap, TCP, UDP, DNS, Raw
import re
# Pattern Identification Functions
def identify_http_patterns(packets):
    """Identify HTTP request patterns."""
    http_requests = []
    for pkt in packets:
        if pkt.haslayer(Raw) and pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
            payload = pkt[Raw].load.decode(errors="ignore")
            if "GET" in payload or "POST" in payload:
                request = payload.splitlines()[0]
                http_requests.append(request)  # Example: "GET /index.html HTTP/1.1"
    return http_requests

def extract_sni_from_payload(payload):
    """
    Extract SNI (Server Name Indication) from a TLS Client Hello message in the raw payload.
    Cleans and validates the extracted SNI.
    """
    try:
        if payload[:2] == b'\x16\x03':  # TLS handshake content type and version
            start_index = payload.find(b'\x00\x00')  # Find the start of the SNI extension
            if start_index > 0:
                sni_length = payload[start_index + 2] * 256 + payload[start_index + 3]
                sni_raw = payload[start_index + 4 : start_index + 4 + sni_length]
                sni = sni_raw.decode("utf-8", errors="ignore")
                
                # Validate the SNI (must match a domain name format)
                if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', sni):
                    return sni
    except Exception:
        pass
    return None

def identify_https_patterns(packets):
    """
    Identify HTTPS patterns by extracting SNI (Server Name Indication) from TLS handshakes.
    """
    tls_handshakes = 0
    observed_domains = []

    for pkt in packets:
        if pkt.haslayer(TCP) and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
                sni = extract_sni_from_payload(payload)
                if sni:
                    tls_handshakes += 1
                    observed_domains.append(sni)
    return {"handshake_count": tls_handshakes, "observed_domains": observed_domains}

def identify_quic_patterns(packets):
    """Identify QUIC traffic based on UDP port 443."""
    quic_patterns = {"packet_count": 0, "total_bytes": 0}
    for pkt in packets:
        if pkt.haslayer(UDP) and (pkt[UDP].dport == 443 or pkt[UDP].sport == 443):
            quic_patterns["packet_count"] += 1
            quic_patterns["total_bytes"] += len(pkt)
    return quic_patterns

def identify_dns_patterns(packets):
    """
    Identify DNS query patterns.
    Extracts queried domain names from DNS packets.
    """
    dns_queries = []
    for pkt in packets:
        # Check for DNS layer (supports both UDP and TCP)
        if pkt.haslayer(DNS) and pkt[DNS].qd:
            queried_name = pkt[DNS].qd.qname.decode(errors="ignore")
            dns_queries.append(queried_name)
    return dns_queries

def identify_ftp_patterns(packets):
    """Identify FTP command patterns."""
    ftp_commands = []
    for pkt in packets:
        if pkt.haslayer(Raw) and pkt.haslayer(TCP) and (pkt[TCP].dport == 21 or pkt[TCP].sport == 21):
            payload = pkt[Raw].load.decode(errors="ignore")
            if any(cmd in payload for cmd in ["USER", "PASS", "RETR", "STOR"]):
                ftp_commands.append(payload.strip())
    return ftp_commands

def identify_smtp_patterns(packets):
    """Identify SMTP command patterns."""
    smtp_commands = []
    for pkt in packets:
        if pkt.haslayer(Raw) and pkt.haslayer(TCP) and (pkt[TCP].dport == 25 or pkt[TCP].sport == 25):
            payload = pkt[Raw].load.decode(errors="ignore")
            if any(cmd in payload for cmd in ["EHLO", "MAIL FROM", "RCPT TO", "DATA"]):
                smtp_commands.append(payload.strip())
    return smtp_commands

def identify_ssh_patterns(packets):
    """Identify SSH banner patterns."""
    ssh_banners = []
    for pkt in packets:
        if pkt.haslayer(Raw) and pkt.haslayer(TCP) and (pkt[TCP].dport == 22 or pkt[TCP].sport == 22):
            payload = pkt[Raw].load.decode(errors="ignore")
            if "SSH-" in payload: 
                ssh_banners.append(payload.strip())
    return ssh_banners

def identify_pattern_by_protocol(file):
    """
    Identify patterns across multiple protocols in the given pcap file.
    Returns a dictionary of identified patterns.
    """
    packets = rdpcap(file)
    patterns = {
        "HTTP": identify_http_patterns(packets),
        "HTTPS": identify_https_patterns(packets),
        "DNS": identify_dns_patterns(packets),
        "FTP": identify_ftp_patterns(packets),
        "SMTP": identify_smtp_patterns(packets),
        "SSH": identify_ssh_patterns(packets),
        "QUIC": identify_quic_patterns(packets),
    }
    return patterns

# Main Execution Block

pcap_file = "top6_capture.pcap" 

# Step 1: Identify patterns
print("\n--- Pattern Identification ---")
patterns = identify_pattern_by_protocol(pcap_file)

# Step 2: Display patterns
print("\n--- Identified Patterns ---")
for protocol, detected_patterns in patterns.items():
    print(f"\n{protocol}:")
    if protocol == "HTTPS" and isinstance(detected_patterns, dict):
        print(f"  - Handshake Count: {detected_patterns['handshake_count']}")
        if detected_patterns['observed_domains']:
            print(f"  - Observed Domains:")
            for domain in detected_patterns['observed_domains']:
                print(f"    - {domain}")
        else:
            print(f"  - No domains (SNI) observed")
    elif protocol == "QUIC" and isinstance(detected_patterns, dict):
        print(f"  - Packet Count: {detected_patterns['packet_count']}")
        print(f"  - Total Bytes: {detected_patterns['total_bytes']}")
    elif isinstance(detected_patterns, list) and detected_patterns:
        for pattern in detected_patterns:
            print(f"  - {pattern}")
    elif isinstance(detected_patterns, int) and detected_patterns > 0:
        print(f"  - Detected Count: {detected_patterns}")
    else:
        print("  - No patterns detected")