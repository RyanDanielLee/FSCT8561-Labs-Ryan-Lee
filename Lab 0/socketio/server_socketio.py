from aiohttp import web
import socketio

# Address and port where the server listens for client connections.
HOST = "127.0.0.1"
PORT = 8080

# Create the asynchronous Socket.IO server and its aiohttp application.
socket_io = socketio.AsyncServer()
app = web.Application()

# Attach Socket.IO routes and event handling to the web application.
socket_io.attach(app)


# Respond to requests sent to the server's root URL.
async def index(request):
    return web.Response(
        text="Hello world from socketio",
        content_type="text/html"
    )


# Runs automatically when a client establishes a Socket.IO connection.
@socket_io.event
async def connect(socket_id, environ):
    print("Connection established:", socket_id)


# Handles the custom "message" event sent by the client.
@socket_io.on("message")
async def print_message(socket_id, data):
    print("Socket ID:", socket_id)
    print("Data:", data)

    message = data["data"]
    reply = "Server Received:" + message

    # Send the reply only to the client that sent the original message.
    await socket_io.emit("reply", {"data": reply}, to=socket_id)


# Runs automatically when a client disconnects.
@socket_io.event
async def disconnect(socket_id):
    print("Disconnected:", socket_id)


# Register the root HTTP route with the aiohttp application.
app.router.add_get("/", index)


# Start the web server only when this file is run directly.
if __name__ == "__main__":
    web.run_app(app, host=HOST, port=PORT)
