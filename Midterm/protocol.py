MAX_MESSAGE_SIZE = 4096

class MessageTooLongError(Exception):
    """Raised when a peer sends a message longer than MAX_MESSAGE_SIZE."""


class ProtocolConnection:
    """One framed connection: wraps a connected TCP socket."""

    def __init__(self, sock):
        self.sock = sock
        self.reader = sock.makefile("rb")

    def send_message(self, message):
        """
        Send one message. The caller supplies the text WITHOUT a newline;
        the newline terminator is added here and nowhere else.
        """
        if "\n" in message or "\r" in message:
            raise ValueError("Message fields may not contain newlines")
        data = (message + "\n").encode("utf-8")
        if len(data) - 1 > MAX_MESSAGE_SIZE:
            raise MessageTooLongError("Message exceeds 4096 bytes")
        self.sock.sendall(data)

    def receive_message(self):
        """
        Return the next message as text (without its terminator).
        Returns None if the peer closed the connection cleanly.
        Raises MessageTooLongError for an over-long message and
        non valid UTF-8; callers handle both as malformed input.
        """
        # Read at most MAX + 2 bytes for one line. The +2 covers the
        # terminator; anything longer than that cannot be a legal message.
        line = self.reader.readline(MAX_MESSAGE_SIZE + 2)
        if not line:
            return None
        if len(line) > MAX_MESSAGE_SIZE + 1:
            raise MessageTooLongError("Message exceeds 4096 bytes")
        if not line.endswith(b"\n"):
            # an incomplete frame, not a message. Discard it 
            return None
        message = line.decode("utf-8")
        # Strip line terminator(s)
        if message.endswith("\n"):
            message = message[:-1]
        if message.endswith("\r"):
            message = message[:-1]
        return message

    def close(self):
        try:
            self.reader.close()
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
