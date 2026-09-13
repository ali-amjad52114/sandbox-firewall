import csv
import os

values = []
with open("data.csv", newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        values.append(float(row["amount"]))

count = len(values)
total = sum(values)
mean = total / count if count else 0.0
maximum = max(values) if values else 0.0

os.makedirs("out", exist_ok=True)
with open("out/report.txt", "w") as f:
    f.write("count=%d\n" % count)
    f.write("mean=%.2f\n" % mean)
    f.write("max=%.2f\n" % maximum)

print("rows=%d mean=%.2f max=%.2f" % (count, mean, maximum))
