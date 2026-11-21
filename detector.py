import math
from collections import Counter

from scapy.all import rdpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
CAPTURE = "captures/normal.pcapng"

# Thresholds: tweak these to make the rules stricter or looser
LONG_NAME_LIMIT = 50
ENTROPY_LIMIT = 3.5
NXDOMAIN_LIMIT = 10  # total failed lookups in one capture before we flag them
# Your normal DNS servers (from Step 2). Add any others ipconfig /all lists.
EXPECTED_DNS_SERVERS = {
    "2001:578:3f::30",
    "2001:578:3f:1::30",
}

def clean(qname):
    """Turn b'www.google.com.' into 'www.google.com'."""
    return qname.decode(errors="replace").rstrip(".")


def shannon_entropy(text):
    """How random a string looks. Higher = more random."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    total = 0.0
    for count in counts.values():
        p = count / length
        total += p * math.log2(p)
    return -total


# Rule 1: long domain names (possible DNS tunneling)
def rule_long_names(domains):
    findings = []
    for domain in domains:
        if len(domain) > LONG_NAME_LIMIT:
            findings.append({"domain": domain, "rule": "long_name", "value": len(domain)})
    return findings


# Rule 2: random-looking first label (possible DGA malware)
def rule_high_entropy(domains):
    findings = []
    for domain in domains:
        first_label = domain.split(".")[0]
        score = shannon_entropy(first_label)
        if score > ENTROPY_LIMIT:
            findings.append({"domain": domain, "rule": "high_entropy", "value": round(score, 2)})
    return findings


# Rule 3: failed lookups (NXDOMAIN = rcode 3)
def rule_nxdomain(packets):
    failed = Counter()
    for pkt in packets:
        if pkt.haslayer(DNSQR) and pkt[DNS].qr == 1 and pkt[DNS].rcode == 3:
            failed[clean(pkt[DNSQR].qname)] += 1
        findings = []
    if sum(failed.values()) >= NXDOMAIN_LIMIT:
        for domain, n in failed.items():
            findings.append({"domain": domain, "rule": "nxdomain", "value": n})
    return findings

# Rule 4: queries sent to a DNS server that isn't one of yours
def rule_unexpected_server(packets):
    seen = set()
    findings = []
    for pkt in packets:
        if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            dst = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst
            domain = clean(pkt[DNSQR].qname)
            if dst not in EXPECTED_DNS_SERVERS and (dst, domain) not in seen:
                seen.add((dst, domain))
                findings.append({"domain": domain, "rule": "unexpected_server", "value": dst})
    return findings


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

# Run every rule and gather the results in one list
findings = []
findings += rule_long_names(counts)
findings += rule_high_entropy(counts)
findings += rule_nxdomain(packets)
findings += rule_unexpected_server(packets)

print()
print(f"Findings: {len(findings)}")
for f in findings:
    print(f"  [{f['rule']}] {f['domain']} ({f['value']})")