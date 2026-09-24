import socket
import nmap


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

            scanner = nmap.PortScanner()

            port_range = (
                str(start_port)
                + "-"
                + str(end_port)
            )

            scanner.scan(
                target_ip,
                port_range
            )

            hosts = scanner.all_hosts()

            if target_ip not in hosts:

                print(
                    "No scan results were returned for the target."
                )

            else:

                protocols = scanner[target_ip].all_protocols()

                if "tcp" in protocols:

                    tcp_ports = scanner[
                        target_ip
                    ]["tcp"]

                    if tcp_ports:

                        print()
                        print(
                            "PORT      STATE      SERVICE"
                        )

                        for port in sorted(
                            tcp_ports.keys()
                        ):

                            state = tcp_ports[
                                port
                            ]["state"]

                            service = tcp_ports[
                                port
                            ]["name"]

                            print(
                                port,
                                state,
                                service
                            )

                    else:

                        print(
                            "No TCP ports were found."
                        )

                else:

                    print(
                        "No TCP results were returned."
                    )

                print()
                print("Scan complete.")

    except ValueError:

        print("Ports must be numbers")

    except nmap.PortScannerError:

        print(
            "Nmap could not perform the scan."
        )