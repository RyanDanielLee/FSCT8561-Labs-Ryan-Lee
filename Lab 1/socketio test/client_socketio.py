import socketio

# Server address and port.
HOST = "127.0.0.1"
PORT = 8080

# Create the Socket.IO client.
sio = socketio.Client()


# Runs automatically after the client connects.
@sio.event
def connect():

    print("connection established")

    username = input("Enter your username: ")

    sio.emit(
        "message",
        {"data": "HELLO|" + username}
    )


# Handles replies from the server.
@sio.on("reply")
def receive_reply(data):

    print("Server:", data["data"])


# Runs automatically when the connection is closed.
@sio.event
def disconnect():

    print("disconnected from server")


# Connect to the Socket.IO server.
sio.connect(
    f"http://{HOST}:{PORT}"
)

# Keep the client running.
while sio.connected:

    message = input(
        "Enter message or type EXIT to leave: "
    )

    if message.upper() == "EXIT":

        sio.disconnect()

    else:

        sio.emit(
            "message",
            {"data": message}
        )