import os

os.makedirs("out", exist_ok=True)
# This write escapes the writable area (workspace root) and must be flagged.
with open("notes.txt", "w") as f:
    f.write("this write escapes to the workspace root\n")
# This write is inside the allowed out/ directory.
with open("out/ok.txt", "w") as f:
    f.write("this write is inside the allowed out/ directory\n")
print("wrote 2 files")
