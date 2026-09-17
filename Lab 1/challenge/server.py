import socket
import threading

HOST = "127.0.0.1"
PORT = 12345

server_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server_socket.bind((HOST, PORT))
server_socket.listen(5)

print("Server is waiting for connections...")

clients = {}


def handle_client(client_socket, client_address):

    username = None
    connected = True

    print("Connected by:", client_address)

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

            command, content = message.split("|", 1)

            if command == "HELLO":

                if content == "":
                    client_socket.send(
                        "ERROR|Username required".encode()
                    )

                else:
                    username = content
                    clients[client_socket] = username

                    print("Username:", username)

                    client_socket.send(
                        ("OK|Hello " + username).encode()
                    )

            elif command == "MSG":

                if username is None:

                    client_socket.send(
                        "ERROR|HELLO required first".encode()
                    )

                elif content == "":

                    client_socket.send(
                        "ERROR|Message cannot be empty".encode()
                    )

                elif len(content) > 200:

                    client_socket.send(
                        "ERROR|Message too long".encode()
                    )

                else:

                    print(username + " says:", content)

                    chat_message = username + ": " + content

                    # Send the message to the other connected clients
                    for other_socket in clients:

                        if other_socket != client_socket:

                            try:
                                other_socket.send(
                                    chat_message.encode()
                                )
                            except ConnectionResetError:
                                pass

                    client_socket.send(
                        (
                            "OK|Message received from "
                            + username
                        ).encode()
                    )

            elif command == "EXIT":

                client_socket.send(
                    "OK|Goodbye".encode()
                )

                connected = False

            else:

                client_socket.send(
                    "ERROR|Unknown command".encode()
                )

        except ConnectionResetError:

            print("Connection reset by client")
            break

    if client_socket in clients:
        del clients[client_socket]

    client_socket.close()

    print("Client connection closed:", client_address)


while True:

    client_socket, client_address = server_socket.accept()

    client_thread = threading.Thread(
        target=handle_client,
        args=(client_socket, client_address)
    )

    client_thread.start()