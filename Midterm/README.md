Operation Sentinel - FSCT 8561 Midterm
Ryan Lee, A01365270

One integrated Python client-server security application built from
Labs 0-5. A threaded TCP server with password and TOTP login, a
client-side port scanner, a client-side HTTP security checker, and
server-side PCAP analysis. Everything runs on localhost only.

Files
protocol.py - message framing shared by the client and server
server.py - the server (127.0.0.1, port 12345)
client.py - the client and menu
scanner.py - port scanner, used by the client
http_checker.py - HTTP checker, used by the client
pcap_analyzer.py - PCAP analysis, used by the server
test_website.py - test website supplied by the instructor (port 8765)
FSCT8561_Operation_Sentinel_Traffic.pcap - capture file supplied by
the instructor, read by the server
requirements.txt - the libraries needed

Setup
Python 3 is needed. Install the libraries with:
python -m pip install -r requirements.txt

Run
Start the three programs in this order, each in its own terminal,
from this folder:
python test_website.py
python server.py
python client.py

Test account: alice, with the Lab 3 password. After the password is
accepted, the server window prints the current 6 digit code. Read it
there and type it into the client when asked.

Client menu: 1 port scan, 2 HTTP security check, 3 PCAP analysis,
4 server status, 5 ping server, 6 exit.

Testing
The tests are documented in Part F of the report and were run
manually. To repeat the main checks, log in with a wrong password
and then with a wrong code and confirm both are denied, send PCAP
from a raw socket with no login and confirm it is denied, run the
three menu checks, stop the test website and run the HTTP check
again to see the connection failure, stop the server while logged
in to see the client report the lost connection, and open
server_log.txt to confirm it records events and contains no
password and no code.