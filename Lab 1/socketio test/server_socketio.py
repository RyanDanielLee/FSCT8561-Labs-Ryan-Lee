from aiohttp import web
import socketio

# Server address and port.
HOST = "127.0.0.1"
PORT = 8080

# Create the Socket.IO server.
socket_io = socketio.AsyncServer()

# Create the aiohttp application.
app = web.Application()

# Attach Socket.IO to the application.
socket_io.attach(app)

# Store connected users.
users = {}


# Respond to requests sent to the root URL.
async def index(request):
    return web.Response(
        text="Hello world from socketio",
        content_type="text/html"
    )


# Runs when a client establishes a connection.
@socket_io.event
async def connect(socket_id, environ):

    print("Connection established:", socket_id)

    users[socket_id] = {
        "username": None
    }


# Handles the "message" event.
@socket_io.on("message")
async def print_message(socket_id, data):

    print("Socket ID:", socket_id)
    print("Data:", data)

    message = data["data"]

    # Store the username when the client sends HELLO.
    if message.startswith("HELLO|"):

        username = message.split("|", 1)[1]

        users[socket_id]["username"] = username

        print("Username:", username)

        await socket_io.emit(
            "reply",
            {"data": "Hello " + username},
            to=socket_id
        )

    # Handle normal chat messages.
    else:

        username = users[socket_id]["username"]

        if username is None:

            await socket_io.emit(
                "reply",
                {"data": "HELLO required first"},
                to=socket_id
            )

        else:

            chat_message = username + ": " + message

            print(chat_message)

            # Send the message to all connected clients.
            await socket_io.emit(
                "reply",
                {"data": chat_message}
            )


# Runs when a client disconnects.
@socket_io.event
async def disconnect(socket_id):

    print("Disconnected:", socket_id)

    if socket_id in users:
        del users[socket_id]


# Register the root HTTP route.
app.router.add_get("/", index)


# Start the server.
if __name__ == "__main__":
    web.run_app(
        app,
        host=HOST,
        port=PORT
    )