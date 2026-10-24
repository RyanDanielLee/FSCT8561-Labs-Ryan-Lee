import socket


def scan_port(target, port):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )
    sock.settimeout(0.5)
    result = sock.connect_ex(
        (target, port)
    )
    sock.close()
    return result == 0


def scan_ports(target, start_port, end_port):

    if target not in ("127.0.0.1", "localhost"):
        raise ValueError(
            "Refused: this scanner only scans authorized local targets "
            "(127.0.0.1 / localhost)"
        )

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError("Invalid hostname or IP address")

    if target_ip != "127.0.0.1":
        raise ValueError(
            "Refused: target does not resolve to this computer (127.0.0.1)"
        )

    if start_port < 1 or start_port > 65535:
        raise ValueError("Invalid start port")
    if end_port < 1 or end_port > 65535:
        raise ValueError("Invalid end port")
    if start_port > end_port:
        raise ValueError("Start port must be less than or equal to end port")
    if end_port - start_port > 1000:
        raise ValueError("Port range is too large")

    lines = []
    lines.append(
        "Scanning TCP ports " + str(start_port) + " to "
        + str(end_port) + " on " + target_ip + " ..."
    )

    open_ports = []

    for port in range(start_port, end_port + 1):
        if scan_port(target_ip, port):
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            lines.append(
                "Port " + str(port) + " is OPEN - " + service
            )
            open_ports.append(port)

    lines.append("Scan complete.")
    if open_ports:
        lines.append(str(len(open_ports)) + " open port(s) found.")
        lines.append("Open ports: " + str(open_ports))
    else:
        lines.append("No open ports found in the selected range.")

    return open_ports, lines
