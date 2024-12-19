import pyshark
import os
import pandas as pd
import matplotlib as plt
import matplotlib.pyplot as plt


os.chdir("Directory/path")
# Open the capture file
cap = pyshark.FileCapture('file_name.pcapng', keep_packets=True)  # Keep packets in memory for iteration

# Try reading the first 5 packets
try:
    packet_count = 0
    for packet in cap:
        packet_count += 1
        if packet_count <= 5:  # Print details for first 5 packets
            print(packet)
    print(f"Number of packets in capture: {packet_count}")
finally:
    cap.close()


data = []
for pkt in cap:
    if 'IP' in pkt:
        data.append({
            'Time': pkt.sniff_time,
            'Source': pkt.ip.src,
            'Destination': pkt.ip.dst,
            'Protocol': pkt.highest_layer,
            'Length': pkt.length
        })

df = pd.DataFrame(data)

protocol_data = df['Protocol'].value_counts()

protocol_data.plot(kind='bar')
plt.title('Traffic by Protocol')
plt.xlabel('Protocol')
plt.ylabel('Packet Count')
plt.show()
