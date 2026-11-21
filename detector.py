from collections import Counter

from scapy.all import rdpcap
from scapy.layers.dns import DNS, DNSQR

CAPTURE = "captures/normal.pcapng"


def clean(qname):
    """Turn b'www.google.com.' into 'www.google.com'."""
    return qname.decode(errors="replace").rstrip(".")


packets = rdpcap(CAPTURE)

# Collect every query name (qr == 0 means it's a question, not an answer)
queries = []
for pkt in packets:
    if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        queries.append(clean(pkt[DNSQR].qname))

counts = Counter(queries)

print("Total queries:", len(queries))
print("Unique domains:", len(counts))
print()
print("Top 10 domains:")
for domain, n in counts.most_common(10):
    print(f"{n:5}  {domain}")