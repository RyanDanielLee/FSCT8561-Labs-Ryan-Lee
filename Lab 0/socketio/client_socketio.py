import socketio

# Server address and port used by the Socket.IO client.
HOST = "127.0.0.1"
PORT = 8080

# Create the client that manages the Socket.IO connection and events.
sio = socketio.Client()

# Runs automatically after the client connects to the server.
@sio.event
def connect():
    print("connection established")

    # Send a custom "message" event with a dictionary payload.
    sio.emit("message", {"data": "Hello this is Ryan"})


# Handles the custom "reply" event sent back by the server.
@sio.on("reply")
def receive_reply(data):
    print("Server replied:", data["data"])

    # End the connection after the server response is received.
    sio.disconnect()


# Runs automatically when the connection is closed.
@sio.event
def disconnect():
    print("disconnected from server")


# Start the connection using the server's HTTP URL.
sio.connect(f"http://{HOST}:{PORT}")

# Keep the client running so it can receive Socket.IO events.
sio.wait()
