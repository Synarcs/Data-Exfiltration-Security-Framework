import matplotlib.pyplot as plt
import numpy as np
import os 


ff = open("dns_metrics.dat", 'r', encoding='utf-8')


lines = [xx.strip() for xx in ff.readlines()]
seconds = []
min_latencies = []
max_latencies = []


ff.close()

for line in lines:
    parts = line.split()
    seconds.append(int(parts[0]))
    min_latencies.append(float(parts[2]) * 1000)  # convert to ms
    max_latencies.append(float(parts[3]) * 1000)  # convert to ms

latency_std = np.std([min_latencies, max_latencies], axis=0)
mean_lat_min, mean_lat_max = np.mean(min_latencies), np.mean(max_latencies)

plt.figure(figsize=(12, 6))
plt.plot(seconds, min_latencies, label="Min Latency (ms)", marker="o", color="green")
plt.plot(seconds, max_latencies, label="Max Latency (ms)", marker="o", color="red")
plt.plot(seconds, latency_std, label="Latency Std Dev (ms)", marker="o", color="blue")

plt.xlabel("Time (seconds)")
plt.ylabel("Latency (ms)")
plt.title("DNS TCP Query Latency Metrics Over Time")
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig("latency_metrics.png", dpi=300)
plt.show()