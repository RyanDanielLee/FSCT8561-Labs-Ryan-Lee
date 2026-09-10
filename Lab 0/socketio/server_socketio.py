from aiohttp import web
import socketio

HOST = "127.0.0.1"
PORT = 8080

socket_io = socketio.AsyncServer()
app = web.Application()
socket_io.attach(app)


async def index(request):
    return web.Response(
        text="Hello world from socketio",
        content_type="text/html"
    )


@socket_io.event
async def connect(socket_id, environ):
    print("Connection established:", socket_id)


@socket_io.on("message")
async def print_message(socket_id, data):
    print("Socket ID:", socket_id)
    print("Data:", data)

    message = data["data"]
    reply = "Server Received:" + message

    await socket_io.emit("reply", {"data": reply}, to=socket_id)


@socket_io.event
async def disconnect(socket_id):
    print("Disconnected:", socket_id)


app.router.add_get("/", index)


if __name__ == "__main__":
    web.run_app(app, host=HOST, port=PORT)
