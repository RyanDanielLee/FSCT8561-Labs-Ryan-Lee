import hashlib
import os
import socket
import threading
import time

import pyotp

from protocol import ProtocolConnection, MessageTooLongError
from pcap_analyzer import analyze_pcap

HOST = "127.0.0.1"
PORT = 12345

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP_FILE = os.path.join(BASE_DIR, "FSCT8561_Operation_Sentinel_Traffic.pcap")
LOG_FILE = os.path.join(BASE_DIR, "server_log.txt")

MAX_AUTH_FAILURES = 3
MAX_OTP_FAILURES = 3

PROTECTED_COMMANDS = ("PING", "STATUS", "PCAP")


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password, stored_hash):
    return hash_password(password) == stored_hash


def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp.strip(), valid_window=1)


# alice / Cyber123!
alice_secret = "JBSWY3DPEHPK3PXP"

users = {
    "alice": {
        "password_hash": hash_password("Cyber123!"),
        "totp_secret": alice_secret
    }
}


# Security event logging
# date/time, event type, username if known, client address, and a short fixed detail string.
# Callers never pass a password or an OTP code into this function.

def log_event(event, username="-", address="-", detail=""):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    line = (
        timestamp + " | " + event + " | user=" + str(username)
        + " | address=" + str(address)
    )
    if detail:
        line = line + " | " + detail
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as log_file:
            log_file.write(line + "\n")
    except OSError:
        # Logging must never crash the service it is observing.
        print("WARNING: could not write to", LOG_FILE)
    print("[LOG]", line)


def handle_client(client_socket, client_address):
    """Handle one connection (runs in its own Lab 1-style thread)."""
    address_text = str(client_address)
    connection = ProtocolConnection(client_socket)

    # Session state for this connection only (stateful model)
    # discarded when the connection closes.
    password_verified = False
    authenticated = False
    authenticated_user = None
    pending_user = None
    auth_failures = 0
    otp_failures = 0

    log_event("CONNECTION_OPEN", address=address_text)
    print("Connected by:", client_address)

    connected = True
    while connected:
        try:
            message = connection.receive_message()
        except MessageTooLongError:
            # Over-long input: reject, log, and drop this connection 
            # its framing is no longer trustworthy.
            log_event("MESSAGE_TOO_LONG",
                      username=authenticated_user or pending_user or "-",
                      address=address_text)
            try:
                connection.send_message("ERROR|Message too long")
            except OSError:
                pass
            break
        except UnicodeDecodeError:
            log_event("INVALID_ENCODING", address=address_text)
            break
        except (ConnectionResetError, OSError):
            print("Connection reset by client", client_address)
            log_event("CONNECTION_RESET",
                      username=authenticated_user or pending_user or "-",
                      address=address_text)
            break

        if message is None:
            print("Client disconnected unexpectedly")
            log_event("DISCONNECTED_UNEXPECTED",
                      username=authenticated_user or pending_user or "-",
                      address=address_text)
            break

        if message == "":
            connection.send_message("ERROR|Invalid command format")
            continue

        parts = message.split("|")
        command = parts[0]

        # ---- Authorization gate (Part C.4): checked before dispatch --
        if command in PROTECTED_COMMANDS and not authenticated:
            log_event("UNAUTHORIZED_COMMAND",
                      username=pending_user or "-",
                      address=address_text,
                      detail="command=" + command)
            connection.send_message("ACCESS_DENIED")
            continue

        # AUTH 
        if command == "AUTH":
            if authenticated:
                connection.send_message("ERROR|Already authenticated")
                continue
            if len(parts) != 3:
                connection.send_message("ERROR|Malformed AUTH message")
                continue

            username = parts[1]
            password = parts[2]

            # Username format is restricted so a username can never
            # inject a newline or a fake entry into the log file.
            if not username.isalnum() or len(username) > 20:
                connection.send_message("ERROR|Invalid username format")
                continue

            if username in users and verify_password(
                    password, users[username]["password_hash"]):
                password_verified = True
                pending_user = username

                current_code = pyotp.TOTP(
                    users[username]["totp_secret"]).now()
                time_left = 30 - (int(time.time()) % 30)
                print("Password verified for:", username)
                print("Valid OTP to enter:", current_code,
                      "(" + str(time_left) + "s remaining)")

                log_event("PASSWORD_VERIFIED", username=username,
                          address=address_text)
                connection.send_message("OTP_REQUIRED")
            else:
                auth_failures = auth_failures + 1
                print("Auth failed for:", username)
                log_event("AUTH_FAILED", username=username,
                          address=address_text,
                          detail="attempt " + str(auth_failures))
                connection.send_message("ACCESS_DENIED")
                if auth_failures >= MAX_AUTH_FAILURES:
                    log_event("CONNECTION_CLOSED_TOO_MANY_FAILURES",
                              username=username, address=address_text)
                    connected = False

        #OTP 
        elif command == "OTP":
            if len(parts) != 2:
                connection.send_message("ERROR|Malformed OTP message")
                continue

            otp_code = parts[1]

            if not password_verified or pending_user is None:
                print("OTP rejected: password not verified first")
                log_event("OTP_OUT_OF_SEQUENCE", address=address_text)
                connection.send_message("ACCESS_DENIED")
                continue

            if len(otp_code) != 6 or not otp_code.isdigit():
                connection.send_message("ERROR|OTP must be 6 digits")
                continue

            secret = users[pending_user]["totp_secret"]
            if verify_otp(secret, otp_code):
                authenticated = True
                authenticated_user = pending_user
                print("Authentication successful for:", authenticated_user)
                log_event("AUTHENTICATED", username=authenticated_user,
                          address=address_text)
                connection.send_message("ACCESS_GRANTED")
            else:
                otp_failures = otp_failures + 1
                print("Invalid OTP for:", pending_user)
                log_event("OTP_FAILED", username=pending_user,
                          address=address_text,
                          detail="attempt " + str(otp_failures))
                connection.send_message("ACCESS_DENIED")
                if otp_failures >= MAX_OTP_FAILURES:
                    log_event("CONNECTION_CLOSED_TOO_MANY_FAILURES",
                              username=pending_user, address=address_text)
                    connected = False

        #Protected commands
        elif command == "PING":
            if len(parts) != 1:
                connection.send_message("ERROR|Malformed PING message")
                continue
            connection.send_message("OK|PONG")

        elif command == "STATUS":
            if len(parts) != 1:
                connection.send_message("ERROR|Malformed STATUS message")
                continue
            connection.send_message(
                "OK|User: " + str(authenticated_user)
                + " | PCAP file: " + os.path.basename(PCAP_FILE)
                + " | Server: Operation Sentinel"
            )

        elif command == "PCAP":
            if len(parts) != 1:
                connection.send_message("ERROR|Malformed PCAP message")
                continue
            log_event("PCAP_REQUESTED", username=authenticated_user,
                      address=address_text)
            try:
                result_lines = analyze_pcap(PCAP_FILE)
            except Exception:
                # The analyzer failing must not kill the server 
                # no traceback or file path is sent to the client
                print("PCAP analysis failed for", client_address)
                log_event("PCAP_FAILED", username=authenticated_user,
                          address=address_text)
                connection.send_message("ERROR|PCAP analysis failed")
                continue
            connection.send_message("PCAP_BEGIN")
            for line in result_lines:
                connection.send_message("PCAP|" + line)
            connection.send_message("PCAP_END")
            log_event("PCAP_COMPLETED", username=authenticated_user,
                      address=address_text)

        # EXIT 
        elif command == "EXIT":
            if len(parts) != 1:
                connection.send_message("ERROR|Malformed EXIT message")
                continue
            connection.send_message("OK|Goodbye")
            log_event("EXIT",
                      username=authenticated_user or pending_user or "-",
                      address=address_text)
            connected = False

        else:
            connection.send_message("ERROR|Unknown command")

    connection.close()
    print("Client connection closed:", client_address)


def main():
    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )
    # Allow the port to be reused when the server is restarted between
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print("Operation Sentinel server is waiting for connections on",
          HOST, PORT)

    totp = pyotp.TOTP(alice_secret)
    seconds_remaining = 30 - (int(time.time()) % 30)
    print("Alice's current test OTP:", totp.now(),
          "(" + str(seconds_remaining) + "s left in current window)")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address)
            )
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("Server stopped by operator")
    finally:
        server_socket.close()
        print("Server closed")


if __name__ == "__main__":
    main()
