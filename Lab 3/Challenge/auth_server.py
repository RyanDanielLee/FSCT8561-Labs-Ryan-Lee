import socket
import hashlib
import pyotp
import time

# Helper Functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, stored_hash):
    return hash_password(password) == stored_hash

def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    # valid_window=1 allows a 30-second clock skew tolerance
    return totp.verify(otp.strip(), valid_window=1)

# User Database (Part 3 & 7)
alice_secret = "JBSWY3DPEHPK3PXP"  # Static base32 secret for testing

users = {
    "alice": {
        "password_hash": hash_password("Cyber123!"),
        "totp_secret": alice_secret
    }
}

HOST = "127.0.0.1"
PORT = 12345

server_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server_socket.bind((HOST, PORT))
server_socket.listen(1)

print("Server is waiting for a connection...")

totp = pyotp.TOTP(alice_secret)
seconds_remaining = 30 - (int(time.time()) % 30)
print(f"Alice's current test OTP: {totp.now()} ({seconds_remaining}s left in current window)")

client_socket, client_address = server_socket.accept()
print("Connected by:", client_address)

# Session State Tracking
password_verified = False
authenticated_user = None
connected = True

# Part 17: Failed-Login Protection
MAX_FAILED_ATTEMPTS = 3
failed_attempts = 0

while connected:

    try:
        data = client_socket.recv(1024)

        if not data:
            print("Client disconnected unexpectedly")
            break

        message = data.decode()
        print("Received:", message)

        if "|" not in message:
            client_socket.send(
                "ERROR|Invalid command format".encode()
            )
            continue

        parts = message.split("|")
        command = parts[0]

        # Part 17: refuse everything once the limit has been reached
        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            print("Blocked: too many failed attempts, request denied")
            client_socket.send(
                "ERROR|Too many failed attempts. Authentication blocked.".encode()
            )
            continue

        if command == "AUTH":

            if len(parts) != 3:
                client_socket.send(
                    "ERROR|Malformed AUTH message".encode()
                )
                continue

            username = parts[1]
            password = parts[2]

            if username in users and verify_password(password, users[username]["password_hash"]):
                password_verified = True
                authenticated_user = username
                
                # Generate fresh OTP right when password succeeds
                current_code = pyotp.TOTP(users[username]["totp_secret"]).now()
                time_left = 30 - (int(time.time()) % 30)
                print(f"Password verified for: {username}")
                print(f"Valid OTP to enter: {current_code} ({time_left}s remaining)")

                client_socket.send(
                    "OTP_REQUIRED".encode()
                )
            else:
                password_verified = False
                authenticated_user = None
                print("Auth failed for:", username)

                failed_attempts += 1
                print("Failed attempts:", failed_attempts, "/", MAX_FAILED_ATTEMPTS)

                if failed_attempts >= MAX_FAILED_ATTEMPTS:
                    print("Too many failed attempts. Authentication blocked.")
                    client_socket.send(
                        "ERROR|Too many failed attempts. Authentication blocked.".encode()
                    )
                else:
                    client_socket.send(
                        "ACCESS_DENIED".encode()
                    )

        elif command == "OTP":

            if len(parts) != 2:
                client_socket.send(
                    "ERROR|Malformed OTP message".encode()
                )
                continue

            otp_code = parts[1]

            if not password_verified or authenticated_user is None:
                print("OTP rejected: Password not verified first")
                client_socket.send(
                    "ACCESS_DENIED".encode()
                )
            else:
                secret = users[authenticated_user]["totp_secret"]

                if verify_otp(secret, otp_code):
                    print("Authentication successful for:", authenticated_user)
                    failed_attempts = 0
                    client_socket.send(
                        "ACCESS_GRANTED".encode()
                    )
                    connected = False
                else:
                    print("Invalid OTP for:", authenticated_user)

                    # a failed OTP means the user must start over with the password
                    password_verified = False
                    authenticated_user = None

                    failed_attempts += 1
                    print("Failed attempts:", failed_attempts, "/", MAX_FAILED_ATTEMPTS)

                    if failed_attempts >= MAX_FAILED_ATTEMPTS:
                        print("Too many failed attempts. Authentication blocked.")
                        client_socket.send(
                            "ERROR|Too many failed attempts. Authentication blocked.".encode()
                        )
                    else:
                        client_socket.send(
                            "ACCESS_DENIED".encode()
                        )

        else:
            client_socket.send(
                "ERROR|Unknown command".encode()
            )

    except ConnectionResetError:
        print("Connection reset by client")
        break

client_socket.close()
server_socket.close()
print("Server closed")