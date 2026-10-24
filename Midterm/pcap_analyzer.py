from scapy.all import rdpcap, IP, TCP, UDP

SCAN_DISTINCT_PORTS = 10
REPEATED_SYN_COUNT = 10
RATE_PACKETS = 20
RATE_WINDOW_SECONDS = 5


def _add_one(counter, key):
    if key in counter:
        counter[key] = counter[key] + 1
    else:
        counter[key] = 1


def _sorted_counts(counter):
    """Return counter items sorted by count, largest first."""
    return sorted(counter.items(), key=lambda item: item[1], reverse=True)


def analyze_pcap(pcap_path):
    packets = rdpcap(pcap_path)
    packets = sorted(packets, key=lambda pkt: float(pkt.time))

    lines = []

    total_packets = len(packets)
    if total_packets == 0:
        lines.append("PCAP summary: the capture contains no packets")
        return lines

    duration = float(packets[-1].time) - float(packets[0].time)

    tcp_count = 0
    udp_count = 0
    other_ip_count = 0

    source_counts = {}
    destination_counts = {}
    destination_port_counts = {}

    syn_ports_by_pair = {}

    syn_count_by_flow = {}
    ack_flows = set()
   
    timestamps = {}
    rate_alerted = []

    for pkt in packets:
        if IP not in pkt:
            continue

        source_ip = pkt[IP].src
        destination_ip = pkt[IP].dst
        _add_one(source_counts, source_ip)
        _add_one(destination_counts, destination_ip)

        if TCP in pkt:
            tcp_count = tcp_count + 1
            destination_port = pkt[TCP].dport
            _add_one(destination_port_counts, destination_port)

            flags = pkt[TCP].flags
            is_syn_only = ("S" in flags) and ("A" not in flags)
            is_ack_only = ("A" in flags) and ("S" not in flags)

            if is_syn_only:
                pair = (source_ip, destination_ip)
                if pair not in syn_ports_by_pair:
                    syn_ports_by_pair[pair] = set()
                syn_ports_by_pair[pair].add(destination_port)
                flow = (source_ip, destination_ip, destination_port)
                _add_one(syn_count_by_flow, flow)
            if is_ack_only:
                ack_flows.add((source_ip, destination_ip,
                               destination_port))
        elif UDP in pkt:
            udp_count = udp_count + 1
            _add_one(destination_port_counts, pkt[UDP].dport)
        else:
            other_ip_count = other_ip_count + 1
            continue

        current_time = float(pkt.time)
        if source_ip not in timestamps:
            timestamps[source_ip] = []
        recent_times = []
        for old_time in timestamps[source_ip]:
            if current_time - old_time <= RATE_WINDOW_SECONDS:
                recent_times.append(old_time)
        timestamps[source_ip] = recent_times
        timestamps[source_ip].append(current_time)
        if len(timestamps[source_ip]) > RATE_PACKETS:
            if source_ip not in rate_alerted:
                rate_alerted.append(source_ip)

    lines.append(
        "Total packets: " + str(total_packets)
        + " over " + format(duration, ".2f") + " seconds"
    )
    lines.append("Total TCP packets: " + str(tcp_count))
    lines.append("Total UDP packets: " + str(udp_count))
    if other_ip_count:
        lines.append("Other IP packets: " + str(other_ip_count))

    lines.append("Packets by source:")
    for ip_address, count in _sorted_counts(source_counts):
        lines.append("  " + ip_address + ": " + str(count))
    lines.append("Packets by destination:")
    for ip_address, count in _sorted_counts(destination_counts):
        lines.append("  " + ip_address + ": " + str(count))
    lines.append("Packets by destination port:")
    for port, count in _sorted_counts(destination_port_counts):
        lines.append("  Port " + str(port) + ": " + str(count))

    detections = []

    for (source_ip, destination_ip), ports in syn_ports_by_pair.items():
        if len(ports) > SCAN_DISTINCT_PORTS:
            detections.append(
                "ALERT Port scan: " + source_ip + " sent SYN packets to "
                + str(len(ports)) + " distinct ports on " + destination_ip
                + " (threshold: more than " + str(SCAN_DISTINCT_PORTS)
                + "). Ports: " + str(sorted(ports))
            )

    for (source_ip, destination_ip, port), count in \
            _sorted_counts(syn_count_by_flow):
        flow = (source_ip, destination_ip, port)
        if count > REPEATED_SYN_COUNT and flow not in ack_flows:
            detections.append(
                "ALERT Repeated SYN: " + source_ip + " sent " + str(count)
                + " SYN packets to " + destination_ip + " port " + str(port)
                + " without completing a handshake (threshold: more than "
                + str(REPEATED_SYN_COUNT) + ")"
            )

    for source_ip in rate_alerted:
        detections.append(
            "ALERT High rate: more than " + str(RATE_PACKETS)
            + " TCP/UDP packets from " + source_ip + " within "
            + str(RATE_WINDOW_SECONDS) + " seconds"
        )

    lines.append("Suspicious patterns detected: " + str(len(detections)))
    for detection in detections:
        lines.append(detection)
    if not detections:
        lines.append("No suspicious patterns detected")

    return lines
