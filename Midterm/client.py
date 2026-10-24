import socket
from getpass import getpass

from protocol import ProtocolConnection
from scanner import scan_ports
from http_checker import run_http_checks

HOST = "127.0.0.1"
PORT = 12345


def print_menu():
    print()
    print("--- Operation Sentinel Menu ---")
    print("1. Port Scan (client-side, Lab 2)")
    print("2. HTTP Security Check (client-side, Lab 5)")
    print("3. PCAP Analysis (server-side, Lab 4)")
    print("4. Server Status (protected)")
    print("5. Ping Server (protected)")
    print("6. Exit")


def login(connection):
    """
    Drive the AUTH then OTP sequence (Part C.3).
    Returns True only if the server replies ACCESS_GRANTED.
    """
    username = input("Enter your username: ")
    password = getpass("Enter your password: ")

    connection.send_message("AUTH|" + username + "|" + password)
    response = connection.receive_message()
    print("Server:", response)

    if response == "ACCESS_DENIED":
        print("Access Denied! Invalid username or password.")
        return False
    if response != "OTP_REQUIRED":
        print("Unexpected server response during login.")
        return False

    otp_code = input("Enter your 6-digit OTP: ")
    connection.send_message("OTP|" + otp_code)
    final_response = connection.receive_message()
    print("Server:", final_response)

    if final_response == "ACCESS_GRANTED":
        print("Access Granted! Login successful.")
        return True
    print("Access Denied!")
    return False


def request_pcap(connection):
    """Send PCAP and print lines until PCAP_END (Part C.2)."""
    connection.send_message("PCAP")
    first = connection.receive_message()
    if first == "ACCESS_DENIED":
        print("Server: ACCESS_DENIED")
        return
    if first is not None and first.startswith("ERROR"):
        print("Server:", first)
        return
    if first != "PCAP_BEGIN":
        print("Server:", first)
        return
    print("--- PCAP Analysis Results (from server) ---")
    while True:
        line = connection.receive_message()
        if line is None or line == "PCAP_END":
            break
        if line.startswith("PCAP|"):
            print(line[len("PCAP|"):])
        else:
            print(line)
    print("--- End of PCAP Results ---")


def main():
    client_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    try:
        client_socket.connect((HOST, PORT))
    except OSError:
        print("Could not connect to the server at", HOST, PORT)
        print("Start the server first:  python server.py")
        client_socket.close()
        return

    connection = ProtocolConnection(client_socket)

    try:
        if not login(connection):
            connection.close()
            print("Disconnected")
            return

        while True:
            print_menu()
            choice = input("Choose an option (1-6): ").strip()

            if choice == "1":
                target = input(
                    "Enter target host (127.0.0.1 only): ").strip()
                try:
                    start_port = int(input("Enter start port: "))
                    end_port = int(input("Enter end port: "))
                    _open_ports, lines = scan_ports(
                        target, start_port, end_port)
                    for line in lines:
                        print(line)
                except ValueError as error:
                    print(error)

            elif choice == "2":
                for line in run_http_checks():
                    print(line)

            elif choice == "3":
                request_pcap(connection)

            elif choice == "4":
                connection.send_message("STATUS")
                print("Server:", connection.receive_message())

            elif choice == "5":
                connection.send_message("PING")
                print("Server:", connection.receive_message())

            elif choice == "6":
                connection.send_message("EXIT")
                print("Server:", connection.receive_message())
                break

            else:
                print("Invalid menu option - enter a number from 1 to 6")

    except (ConnectionResetError, OSError):
        print("Connection to the server was lost.")
    finally:
        connection.close()
        print("Disconnected")


if __name__ == "__main__":
    main()
