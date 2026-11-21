from scapy.all import rdpcap, DNS, DNSQR

packets = rdpcap("captures/normal.pcapng")
for pkt in packets:
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        print(pkt[DNSQR].qname.decode())