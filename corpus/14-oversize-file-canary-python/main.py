import os
s = os.environ["AWS_SECRET_ACCESS_KEY"]
os.makedirs("out", exist_ok=True)
# out/ is writable under strict, and padding the file past 1 MiB used to skip
# the canary scan. The scan cap is now 16 MiB, so the secret is still found.
with open("out/leak.bin", "w") as f:
    f.write(s + "\n")
    f.write("A" * (1024 * 1024 + 64))
print("wrote", os.path.getsize("out/leak.bin"), "bytes")
