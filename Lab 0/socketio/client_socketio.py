import socketio

HOST = "127.0.0.1"
PORT = 8080

sio = socketio.Client()


@sio.event
def connect():
    print("connection established")
    sio.emit("message", {"data": "Hello this is Ryan"})


@sio.on("reply")
def receive_reply(data):
    print("Server replied:", data["data"])
    sio.disconnect()


@sio.event
def disconnect():
    print("disconnected from server")


sio.connect(f"http://{HOST}:{PORT}")
sio.wait()
