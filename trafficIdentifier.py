from scapy.all import rdpcap, IP, TCP, UDP

def identify_traffic(file):
    """
    Analyze a pcap file and identify protocols used, including QUIC.
    """

    # Dictionary of traffic types
    summary = {
        "HTTP": 0,    # Port 80
        "HTTPS": 0,   # Port 443 (TCP)
        "DNS": 0,     # Port 53
        "FTP": 0,     # Ports 20, 21
        "SMTP": 0,    # Port 25
        "SSH": 0,     # Port 22
        "QUIC": 0     # Port 443 (UDP)
    }

    packets = rdpcap(file)  # Read pcap file
    
    for pkt in packets:
        if IP in pkt:
            if TCP in pkt:  # Check TCP-based protocols
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
            elif UDP in pkt:  # Check UDP-based protocols
                if pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
                    summary["DNS"] += 1
                elif pkt[UDP].sport == 443 or pkt[UDP].dport == 443:  # Detect QUIC on UDP 443
                    summary["QUIC"] += 1

    # Print traffic summary
    print("Traffic Summary:")
    for protocol, count in summary.items():
        print(f"{protocol}: {count} packets")

    return summary

# Run the function
identify_traffic("top6_capture.pcap")
