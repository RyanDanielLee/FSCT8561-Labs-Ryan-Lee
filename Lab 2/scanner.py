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

    if result == 0:
        return True
    else:
        return False


target = input("Enter target host: ")


try:

    target_ip = socket.gethostbyname(target)

    print("Target:", target_ip)

except socket.gaierror:

    print("Invalid hostname or IP address")

    target_ip = None


if target_ip is not None:

    try:

        start_port = int(
            input("Enter start port: ")
        )

        end_port = int(
            input("Enter end port: ")
        )

        if start_port < 1 or start_port > 65535:

            print("Invalid start port")

        elif end_port < 1 or end_port > 65535:

            print("Invalid end port")

        elif start_port > end_port:

            print(
                "Start port must be less than or equal to end port"
            )

        elif end_port - start_port > 1000:

            print("Port range is too large")

        else:

            print(
                "Scanning TCP ports",
                start_port,
                "to",
                end_port,
                "..."
            )

            open_ports = []

            for port in range(
                start_port,
                end_port + 1
            ):

                if scan_port(
                    target_ip,
                    port
                ):

                    try:

                        service = socket.getservbyport(
                            port,
                            "tcp"
                        )

                    except OSError:

                        service = "unknown"

                    print(
                        "Port",
                        port,
                        "is OPEN",
                        "-",
                        service
                    )

                    open_ports.append(port)

            print()
            print("Scan complete.")

            if open_ports:

                print(
                    len(open_ports),
                    "open port(s) found."
                )

                print(
                    "Open ports:",
                    open_ports
                )

            else:

                print(
                    "No open ports found in the selected range."
                )

    except ValueError:

        print("Ports must be numbers")