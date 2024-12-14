from scapy.all import rdpcap, IP, TCP, UDP

def identify_traffic(file):
    """
    Analyze a pcap file and identify protocols used.
    """

    #Dict of traffic types
    summary = {
        "HTTP": 0, #Port 80
        "HTTPS": 0, #443
        "DNS": 0, #53
        "FTP": 0, #20, 21
        "SMTP": 0, #25
        "SSH": 0 #22
    }



    packets = rdpcap(file)
    
    for pkt in packets:
        if IP in pkt:
            if TCP in pkt:
                if pkt[TCP].sport == 80 or pkt[TCP].dport == 80:
                    summary["HTTP"] += 1
                elif pkt[TCP].sport == 443 or pkt[TCP].dport == 443:
                    summary["HTTPS"] += 1
                elif pkt[TCP].sport == 20 or pkt[TCP].dport == 20 or pkt[TCP].sport == 21 or pkt[TCP].dport == 21:
                    summary["FTP"] += 1
                elif pkt[TCP].sport == 25 or pkt[TCP].dport == 25:
                    summary["SMTP"] += 1      
                elif pkt[TCP].sport == 22 or pkt[TCP].dport == 22:
                    summary["SSH"] += 1
            elif UDP in pkt:
                if pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
                    summary["DNS"] += 1


    print("Traffic Summary:", summary)
    for protocal, count in summary.items():
        print(f"{protocal}: {count} packets")
    return summary

identify_traffic("top6_capture.pcap")