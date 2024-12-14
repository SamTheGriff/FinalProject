from scapy.all import rdpcap, TCP, UDP, Raw
import sqlite3

# Pattern Identification Functions
def identify_http_patterns(packets):
    http_requests = []
    for pkt in packets:
        if pkt.haslayer(Raw) and pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
            payload = pkt[Raw].load.decode(errors="ignore")
            if "GET" in payload or "POST" in payload:
                http_requests.append(payload.splitlines()[0])
    return http_requests

def identify_https_patterns(packets):
    tls_handshakes = 0
    for pkt in packets:
        if pkt.haslayer(TCP) and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
                if b'\x16\x03' in payload:
                    tls_handshakes += 1
    return tls_handshakes

def identify_dns_patterns(packets):
    dns_queries = []
    for pkt in packets:
        if pkt.haslayer(UDP) and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53):
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode(errors="ignore")
                if "www" in payload or ".com" in payload:
                    dns_queries.append(payload)
    return dns_queries

def identify_ftp_patterns(packets):
    ftp_commands = []
    for pkt in packets:
        if pkt.haslayer(Raw) and pkt.haslayer(TCP) and (pkt[TCP].dport == 21 or pkt[TCP].sport == 21):
            payload = pkt[Raw].load.decode(errors="ignore")
            if any(cmd in payload for cmd in ["USER", "PASS", "RETR", "STOR"]):
                ftp_commands.append(payload.strip())
    return ftp_commands

def identify_smtp_patterns(packets):
    smtp_commands = []
    for pkt in packets:
        if pkt.haslayer(Raw) and pkt.haslayer(TCP) and (pkt[TCP].dport == 25 or pkt[TCP].sport == 25):
            payload = pkt[Raw].load.decode(errors="ignore")
            if any(cmd in payload for cmd in ["EHLO", "MAIL FROM", "RCPT TO", "DATA"]):
                smtp_commands.append(payload.strip())
    return smtp_commands

def identify_ssh_patterns(packets):
    ssh_attempts = 0
    for pkt in packets:
        if pkt.haslayer(TCP) and (pkt[TCP].dport == 22 or pkt[TCP].sport == 22):
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode(errors="ignore")
                if "SSH-" in payload:
                    ssh_attempts += 1
    return ssh_attempts

def identify_pattern_by_protocol(file):
    packets = rdpcap(file)
    return {
        "HTTP": identify_http_patterns(packets),
        "HTTPS": identify_https_patterns(packets),
        "DNS": identify_dns_patterns(packets),
        "FTP": identify_ftp_patterns(packets),
        "SMTP": identify_smtp_patterns(packets),
        "SSH": identify_ssh_patterns(packets),
    }

# Database Setup and Purpose Analysis
def setup_pattern_database(db_file="patterns.db"):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol TEXT,
            pattern TEXT,
            purpose TEXT
        )
    ''')
    known_patterns = [
        ("HTTP", "GET /index.html", "Normal Web Browsing"),
        ("HTTPS", "TLS Handshake", "Secure Web Browsing"),
        ("DNS", "www.example.com", "Domain Resolution"),
        ("FTP", "USER admin", "File Transfer Login Attempt"),
        ("SMTP", "MAIL FROM:<user@example.com>", "Email Sending"),
        ("SSH", "SSH-", "Remote Server Access"),
        ("HTTP", "POST /login", "User Authentication")
    ]
    cursor.executemany('''
        INSERT OR IGNORE INTO traffic_patterns (protocol, pattern, purpose)
        VALUES (?, ?, ?)
    ''', known_patterns)
    conn.commit()
    conn.close()

def analyze_purpose(patterns, db_file="patterns.db"):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    results = {}
    for protocol, detected_patterns in patterns.items():
        if isinstance(detected_patterns, int):
            if protocol == "HTTPS" and detected_patterns > 0:
                results[protocol] = "Secure Web Browsing (TLS Handshakes detected)"
            continue
        results[protocol] = []
        for pattern in detected_patterns:
            cursor.execute("SELECT purpose FROM traffic_patterns WHERE protocol = ? AND pattern LIKE ?", 
                           (protocol, f"%{pattern}%"))
            match = cursor.fetchone()
            if match:
                results[protocol].append(match[0])
            else:
                results[protocol].append("Unknown Purpose")
    conn.close()
    return results

# Main Execution Block
if __name__ == "__main__":
    pcap_file = "top6_capture.pcap"  # Replace with your pcap file path

    # Step 1: Setup database
    setup_pattern_database()

    # Step 2: Identify patterns
    print("\n--- Identifying Traffic Patterns ---")
    patterns = identify_pattern_by_protocol(pcap_file)

    # Step 3: Analyze purpose
    print("\n--- Analyzing Traffic Purpose ---")
    results = analyze_purpose(patterns)

    # Step 4: Display results
    print("\n--- Purpose Identification Results ---")
    for protocol, purposes in results.items():
        print(f"{protocol}:")
        if isinstance(purposes, list):
            for purpose in purposes:
                print(f"  - {purpose}")
        else:
            print(f"  - {purposes}")
