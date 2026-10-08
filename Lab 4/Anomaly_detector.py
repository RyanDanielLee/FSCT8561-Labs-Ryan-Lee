from scapy.all import rdpcap, IP, TCP, UDP

packets = rdpcap("botnet-capture-20110812-rbot.pcap")

tcp_count = 0
udp_count = 0
timestamps = {}
alerted = []

packets = sorted(packets, key=lambda pkt: float(pkt.time))

for pkt in packets:
    if IP in pkt:
        if TCP in pkt:
            tcp_count = tcp_count + 1
        elif UDP in pkt:
            udp_count = udp_count + 1
        else:
            continue

        source_ip = pkt[IP].src
        current_time = float(pkt.time)

        if source_ip not in timestamps:
            timestamps[source_ip] = []

        recent_times = []

        for old_time in timestamps[source_ip]:
            if current_time - old_time <= 5:
                recent_times.append(old_time)

        timestamps[source_ip] = recent_times
        timestamps[source_ip].append(current_time)

        if len(timestamps[source_ip]) > 20:
            if source_ip not in alerted:
                print("ALERT: More than 20 IPv4 TCP/UDP packets from", source_ip,
                      "within 5 seconds")
                alerted.append(source_ip)

print()
print("Total TCP packets:", tcp_count)
print("Total UDP packets:", udp_count)
print("Suspicious IPs:", len(alerted))