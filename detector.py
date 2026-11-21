"""DNS anomaly detector: flags suspicious DNS lookups in a pcap file."""
import argparse
import csv
import math
from collections import Counter

from scapy.all import rdpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

NXDOMAIN_LIMIT = 10  # total failed lookups in one capture before we flag them

# Your normal DNS servers (from Step 2). Add any others ipconfig /all lists.
EXPECTED_DNS_SERVERS = {
    "2001:578:3f::30",
    "2001:578:3f:1::30",
}

# Short names for the summary line
RULE_LABELS = {
    "high_entropy": "entropy",
    "long_name": "length",
    "nxdomain": "NXDOMAIN",
    "unexpected_server": "resolver",
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
def rule_long_names(domains, limit):
    findings = []
    for domain in domains:
        if len(domain) > limit:
            findings.append({"domain": domain, "rule": "long_name", "value": len(domain)})
    return findings


# Rule 2: random-looking first label (possible DGA malware)
def rule_high_entropy(domains, limit):
    findings = []
    for domain in domains:
        first_label = domain.split(".")[0]
        score = shannon_entropy(first_label)
        if score > limit:
            findings.append({"domain": domain, "rule": "high_entropy", "value": round(score, 2)})
    return findings


# Rule 3: failed lookups (NXDOMAIN = rcode 3)
def rule_nxdomain(packets, limit):
    failed = Counter()
    for pkt in packets:
        if pkt.haslayer(DNSQR) and pkt[DNS].qr == 1 and pkt[DNS].rcode == 3:
            failed[clean(pkt[DNSQR].qname)] += 1
    findings = []
    if sum(failed.values()) >= limit:
        for domain, n in failed.items():
            findings.append({"domain": domain, "rule": "nxdomain", "value": n})
    return findings


# Rule 4: queries sent to a DNS server that isn't one of yours
def rule_unexpected_server(packets, servers):
    seen = set()
    findings = []
    for pkt in packets:
        if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            dst = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst
            domain = clean(pkt[DNSQR].qname)
            if dst not in servers and (dst, domain) not in seen:
                seen.add((dst, domain))
                findings.append({"domain": domain, "rule": "unexpected_server", "value": dst})
    return findings


def parse_args():
    parser = argparse.ArgumentParser(description="Flag suspicious DNS lookups in a pcap file.")
    parser.add_argument("pcap", help="path to a .pcap or .pcapng file")
    parser.add_argument("--output", help="save findings to this CSV file")
    parser.add_argument("--entropy", type=float, default=3.5,
                        help="flag first labels with entropy above this (default: 3.5)")
    parser.add_argument("--length", type=int, default=50,
                        help="flag domain names longer than this (default: 50)")
    return parser.parse_args()


def write_csv(findings, path):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "rule", "value"])
        writer.writeheader()
        writer.writerows(findings)


def main():
    args = parse_args()
    packets = rdpcap(args.pcap)

    # Collect every query name (qr == 0 means it's a question, not an answer)
    queries = []
    for pkt in packets:
        if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            queries.append(clean(pkt[DNSQR].qname))
    counts = Counter(queries)

    print("Top 10 domains:")
    for domain, n in counts.most_common(10):
        print(f"{n:5}  {domain}")

    # Run every rule and gather the results in one list
    findings = []
    findings += rule_long_names(counts, args.length)
    findings += rule_high_entropy(counts, args.entropy)
    findings += rule_nxdomain(packets, NXDOMAIN_LIMIT)
    findings += rule_unexpected_server(packets, EXPECTED_DNS_SERVERS)

    print()
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['rule']}] {f['domain']} ({f['value']})")

    if args.output:
        write_csv(findings, args.output)
        print(f"\nReport saved to {args.output}")

    # Summary line
    per_rule = Counter(f["rule"] for f in findings)
    flagged = len({f["domain"] for f in findings})
    breakdown = ", ".join(f"{label}: {per_rule[rule]}" for rule, label in RULE_LABELS.items())
    print(f"\n{len(queries)} queries analyzed, {flagged} domains flagged ({breakdown})")


if __name__ == "__main__":
    main()