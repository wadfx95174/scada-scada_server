from scapy.all import *

pcap = rdpcap("/home/pi/Desktop/pcap/1.pcap")
print(pcap[49].show())
print(pcap[214].show())
# for packet in pcap:
#     if pcaket.haslayer(Raw):
#         print(packet.show())