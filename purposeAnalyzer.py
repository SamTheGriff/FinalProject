from scapy.all import rdpcap, IP, TCP, UDP
import sqlite3

# Function to identify traffic in a pcap file
def identify_traffic(file):
    """
    Analyze a pcap file and identify protocols used, including QUIC.
    """
    summary = {
        "HTTP": 0,   # Port 80
        "HTTPS": 0,  # Port 443 (TCP)
        "DNS": 0,    # Port 53
        "FTP": 0,    # Ports 20, 21
        "SMTP": 0,   # Port 25
        "SSH": 0,    # Port 22
        "QUIC": {"packet_count": 0, "total_bytes": 0}  # UDP 443 for QUIC
    }

    packets = rdpcap(file)
    
    for pkt in packets:
        if IP in pkt:
            if TCP in pkt:
                if pkt[TCP].sport == 80 or pkt[TCP].dport == 80:
                    summary["HTTP"] += 1
                elif pkt[TCP].sport == 443 or pkt[TCP].dport == 443:
                    summary["HTTPS"] += 1
                elif pkt[TCP].sport in [20, 21] or pkt[TCP].dport in [20, 21]:
                    summary["FTP"] += 1
                elif pkt[TCP].sport == 25 or pkt[TCP].dport == 25:
                    summary["SMTP"] += 1
                elif pkt[TCP].sport == 22 or pkt[TCP].dport == 22:
                    summary["SSH"] += 1
            elif UDP in pkt:
                if pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
                    summary["DNS"] += 1
                elif pkt[UDP].sport == 443 or pkt[UDP].dport == 443:  # Detect QUIC on UDP 443
                    summary["QUIC"]["packet_count"] += 1
                    summary["QUIC"]["total_bytes"] += len(pkt)

    return summary

# Database setup and analysis
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
        ("HTTP", "POST /login", "User Authentication"),
        ("HTTPS", "TLS Handshake", "Secure Web Browsing"),
        ("DNS", "www.example.com", "Domain Resolution"),
        ("FTP", "USER admin", "File Transfer Login Attempt"),
        ("SMTP", "MAIL FROM:<user@example.com>", "Email Sending"),
        ("SSH", "SSH-", "Remote Server Access"),
        ("QUIC", "UDP 443", "Video Streaming or Encrypted Media Traffic (e.g., YouTube)")
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
        # Special handling for QUIC
        if protocol == "QUIC" and isinstance(detected_patterns, dict):
            results["QUIC"] = (f"{detected_patterns['packet_count']} packets, "
                               f"{detected_patterns['total_bytes']} bytes transferred "
                               f"(QUIC Traffic, likely Video Streaming from YouTube)")
            continue

        if isinstance(detected_patterns, int) and detected_patterns > 0:
            if protocol == "HTTPS":
                results[protocol] = "Secure Web Browsing (TLS Handshakes detected)"
            elif protocol == "HTTP":
                results[protocol] = "Normal Web Browsing"
            elif protocol == "DNS":
                results[protocol] = "Domain Resolution or DNS Queries"
            elif protocol == "FTP":
                results[protocol] = "File Transfer Activity"
            elif protocol == "SMTP":
                results[protocol] = "Email Sending or Receiving"
            elif protocol == "SSH":
                results[protocol] = "Remote Server Access"
            continue

        results[protocol] = "No Significant Purpose Identified"

    conn.close()
    return results

# Main execution
if __name__ == "__main__":
    pcap_file = "top6_capture.pcap" 

    # Step 1: Set up the pattern database
    setup_pattern_database()

    # Step 2: Identify traffic
    print("\n--- Identifying Traffic ---")
    traffic_summary = identify_traffic(pcap_file)

    # Step 3: Analyze purpose
    print("\n--- Analyzing Traffic Purpose ---")
    results = analyze_purpose(traffic_summary)

    # Step 4: Display results
    print("\n--- Purpose Identification Results ---")
    for protocol, purpose in results.items():
        print(f"{protocol}: {purpose}")
