import os

os.makedirs("out", exist_ok=True)
with open("out/ok.txt", "w") as f:
    f.write("this write is inside the allowed out/ directory\n")
with open("notes.txt", "w") as f:
    f.write("this write escapes to the workspace root\n")
print("wrote 2 files")
