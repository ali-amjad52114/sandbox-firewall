import urllib.request

with urllib.request.urlopen("http://example.com", timeout=10) as resp:
    resp.read()
    print("status", resp.status)
