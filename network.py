from scapy.all import sniff, PcapWriter, TCP, UDP, Raw

def capture_top_6_traffic(duration=30, output_file="top6_capture.pcap"):
    """
    Capture network traffic for HTTP, HTTPS, DNS, FTP, SMTP, SSH.
    Monitors QUIC-based traffic (Youtube) over UDP 443.
    """
    # Define a BPF filter for the top 6 protocols and QUIC
    bpf_filter = (
        "tcp port 80 or "     # HTTP
        "tcp port 443 or "    # HTTPS
        "udp port 53 or "     # DNS
        "tcp port 20 or "     # FTP-Data
        "tcp port 21 or "     # FTP-Control
        "tcp port 587 or "    # SMTP
        "tcp port 22 or "     # SSH
        "udp port 443"        # QUIC (YouTube Streaming)
    )

    print(f"Capturing traffic for the top 6 protocols and QUIC with filter: {bpf_filter}")
    print(f"Duration: {duration} seconds. Output file: {output_file}")

    # Track YouTube streaming patterns
    streaming_patterns = {"mpd": 0, "mp4": 0, "webm": 0, "quic_packets": 0}

    def packet_callback(pkt):
        """
        Process each packet in real-time to detect streaming patterns.
        """
        nonlocal streaming_patterns

        try:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode(errors="ignore")

                # Look for MPEG-DASH manifest and video segment files
                if ".mpd" in payload:
                    streaming_patterns["mpd"] += 1
                    print("YouTube Streaming Detected: MPEG-DASH Manifest (.mpd)")
                elif ".mp4" in payload:
                    streaming_patterns["mp4"] += 1
                    print("YouTube Streaming Detected: Video Segment (.mp4)")
                elif ".webm" in payload:
                    streaming_patterns["webm"] += 1
                    print("YouTube Streaming Detected: Video Segment (.webm)")

            elif pkt.haslayer(UDP) and pkt[UDP].dport == 443:
                streaming_patterns["quic_packets"] += 1
        except Exception:
            pass  # Ignore packets that cannot be decoded or processed

    # Capture packets with the filter and apply the callback
    packets = sniff(filter=bpf_filter, timeout=duration, prn=packet_callback)

    # Save packets to a pcap file
    with PcapWriter(output_file, linktype=1) as pcap_writer:
        for pkt in packets:
            pcap_writer.write(pkt)

    print("\n--- Capture Summary ---")
    print(f"Total packets captured: {len(packets)}")
    print(f"Saved packets to {output_file}")

    return output_file

# Run the function
if __name__ == "__main__":
    capture_top_6_traffic()
