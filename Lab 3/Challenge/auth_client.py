import socket
from getpass import getpass

HOST = "127.0.0.1"
PORT = 12345

client_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

client_socket.connect((HOST, PORT))

# Part 17: keep asking until access is granted or the user chooses to stop
keep_trying = True

while keep_trying:

    username = input("Enter your username: ")
    password = getpass("Enter your password: ")

    auth_message = "AUTH|" + username + "|" + password
    #test 6
    # auth_message = "OTP|123456"
    #test 7
    # auth_message = "AUTH|alice"

    client_socket.send(
        auth_message.encode()
    )

    response = client_socket.recv(1024).decode()
    print("Server:", response)

    if response == "OTP_REQUIRED":

        otp_code = input("Enter your 6-digit OTP: ")

        otp_message = "OTP|" + otp_code

        client_socket.send(
            otp_message.encode()
        )

        final_response = client_socket.recv(1024).decode()

        print("Server:", final_response)

        if final_response == "ACCESS_GRANTED":
            print("Access Granted! Login successful.")
            keep_trying = False
        elif final_response.startswith("ERROR|Too many failed attempts"):
            print("Authentication blocked.")
        else:
            print("Access Denied!")

    elif response == "ACCESS_DENIED":
        print("Access Denied! Invalid username or password.")

    elif response.startswith("ERROR|Too many failed attempts"):
        print("Authentication blocked.")

    else:
        # any other ERROR message (e.g. malformed): stop like before
        keep_trying = False

    if keep_trying:
        again = input("Try again? (y/n): ")

        if again.lower() != "y":
            keep_trying = False

client_socket.close()
print("Disconnected")
