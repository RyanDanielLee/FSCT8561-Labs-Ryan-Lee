from scapy.all import rdpcap, IP, TCP, UDP

packets = rdpcap("botnet-capture-20110812-rbot.pcap")

tcp_count = 0
udp_count = 0
shown = 0

for pkt in packets:
    if IP in pkt:
        if TCP in pkt:
            tcp_count = tcp_count + 1

            if shown < 20:
                print("Source:", pkt[IP].src,
                      "Destination:", pkt[IP].dst,
                      "Protocol: TCP",
                      "Source port:", pkt[TCP].sport,
                      "Destination port:", pkt[TCP].dport)
                shown = shown + 1

        elif UDP in pkt:
            udp_count = udp_count + 1

            if shown < 20:
                print("Source:", pkt[IP].src,
                      "Destination:", pkt[IP].dst,
                      "Protocol: UDP",
                      "Source port:", pkt[UDP].sport,
                      "Destination port:", pkt[UDP].dport)
                shown = shown + 1

print()
print("Total TCP packets:", tcp_count)
print("Total UDP packets:", udp_count)