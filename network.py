from scapy.all import sniff, PcapWriter

def capture_top_6_traffic(duration=30, output_file="top6_capture.pcap"):
    """
    Capture network traffic specifically for the top 6 types:
    HTTP, HTTPS, DNS, FTP, SMTP, and SSH.
    """
    # Define a BPF filter for the top 6 network traffic types
    bpf_filter = (
        "tcp port 80 or "     # HTTP
        "tcp port 443 or "    # HTTPS
        "udp port 53 or "     # DNS
        "tcp port 20 or "     # FTP-Data
        "tcp port 21 or "     # FTP-Control
        "tcp port 587 or "     # SMTP
        "tcp port 22"         # SSH
    )
    
    print(f"Capturing traffic for the top 6 protocols with filter: {bpf_filter}")
    print(f"Duration: {duration} seconds. Output file: {output_file}")
    
    # Capture packets matching the filter
    packets = sniff(filter=bpf_filter, timeout=duration)
    
    # Save packets to a pcap file
    with PcapWriter(output_file, linktype=1) as pcap_writer:
        for pkt in packets:
            pcap_writer.write(pkt)
    
    print(f"Saved {len(packets)} packets to {output_file}")
    return output_file

capture_top_6_traffic()