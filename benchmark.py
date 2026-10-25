#!/usr/bin/env python3
"""
Benchmark script for DPI Packet Analyzer.
Generates PCAPs of various sizes and benchmarks single-threaded vs multi-threaded performance.
"""

import subprocess
import time
import os
import sys
import statistics
import struct
import random

# Import the PCAP generation functions from generate_test_pcap.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reuse the PCAP generation code
class PCAPWriter:
    def __init__(self, filename):
        self.file = open(filename, 'wb')
        self.write_global_header()
        self.timestamp = 1700000000

    def write_global_header(self):
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(header)

    def write_packet(self, data):
        ts_sec = self.timestamp
        ts_usec = random.randint(0, 999999)
        self.timestamp += 1

        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        self.file.write(pkt_header)
        self.file.write(data)

    def close(self):
        self.file.close()

def create_ethernet_header(src_mac, dst_mac, ethertype=0x0800):
    return bytes.fromhex(dst_mac.replace(':', '')) + \
           bytes.fromhex(src_mac.replace(':', '')) + \
           struct.pack('>H', ethertype)

def create_ip_header(src_ip, dst_ip, protocol, payload_len):
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(1, 65535)
    flags_frag = 0x4000
    ttl = 64
    checksum = 0

    header = struct.pack('>BBHHHBBH',
                         version_ihl, tos, total_len,
                         ident, flags_frag,
                         ttl, protocol, checksum)

    header += bytes([int(x) for x in src_ip.split('.')])
    header += bytes([int(x) for x in dst_ip.split('.')])

    return header

def create_tcp_header(src_port, dst_port, seq, ack, flags, payload_len=0):
    data_offset = 5 << 4
    window = 65535
    checksum = 0
    urgent = 0

    return struct.pack('>HHIIBBHHH',
                       src_port, dst_port,
                       seq, ack,
                       data_offset, flags,
                       window, checksum, urgent)

def create_udp_header(src_port, dst_port, payload_len):
    length = 8 + payload_len
    checksum = 0
    return struct.pack('>HHHH', src_port, dst_port, length, checksum)

def create_tls_client_hello(sni):
    sni_bytes = sni.encode('ascii')
    sni_entry = struct.pack('>BH', 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list

    supported_versions = struct.pack('>HHB', 0x002b, 3, 2) + struct.pack('>H', 0x0304)

    extensions = sni_ext + supported_versions
    extensions_data = struct.pack('>H', len(extensions)) + extensions

    client_version = struct.pack('>H', 0x0303)
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    session_id = struct.pack('B', 0)
    cipher_suites = struct.pack('>H', 4) + struct.pack('>HH', 0x1301, 0x1302)
    compression = struct.pack('BB', 1, 0)

    client_hello_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_data

    handshake = struct.pack('B', 0x01)
    handshake += struct.pack('>I', len(client_hello_body))[1:]
    handshake += client_hello_body

    record = struct.pack('B', 0x16)
    record += struct.pack('>H', 0x0301)
    record += struct.pack('>H', len(handshake))
    record += handshake

    return record

def create_http_request(host, path='/'):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DPI-Test/1.0\r\nAccept: */*\r\n\r\n".encode()

def create_dns_query(domain):
    txid = struct.pack('>H', random.randint(1, 65535))
    flags = struct.pack('>H', 0x0100)
    counts = struct.pack('>HHHH', 1, 0, 0, 0)

    question = b''
    for label in domain.split('.'):
        question += struct.pack('B', len(label)) + label.encode()
    question += struct.pack('B', 0)
    question += struct.pack('>HH', 1, 1)

    return txid + flags + counts + question


def generate_pcap(filename, num_tls=100, num_http=20, num_dns=20, num_blocked=10):
    """Generate a PCAP with specified number of connections."""
    writer = PCAPWriter(filename)

    user_mac = '00:11:22:33:44:55'
    user_ip = '192.168.1.100'
    gateway_mac = 'aa:bb:cc:dd:ee:ff'

    # TLS connections
    tls_connections = [
        ('142.250.185.206', 'www.google.com', 443),
        ('142.250.185.110', 'www.youtube.com', 443),
        ('157.240.1.35', 'www.facebook.com', 443),
        ('157.240.1.174', 'www.instagram.com', 443),
        ('104.244.42.65', 'twitter.com', 443),
        ('52.94.236.248', 'www.amazon.com', 443),
        ('23.52.167.61', 'www.netflix.com', 443),
        ('140.82.114.4', 'github.com', 443),
        ('104.16.85.20', 'discord.com', 443),
        ('35.186.224.25', 'zoom.us', 443),
        ('35.186.227.140', 'web.telegram.org', 443),
        ('99.86.0.100', 'www.tiktok.com', 443),
        ('35.186.224.47', 'open.spotify.com', 443),
        ('192.0.78.24', 'www.cloudflare.com', 443),
        ('13.107.42.14', 'www.microsoft.com', 443),
        ('17.253.144.10', 'www.apple.com', 443),
    ]

    http_connections = [
        ('93.184.216.34', 'example.com', 80),
        ('185.199.108.153', 'httpbin.org', 80),
    ]

    dns_queries = [
        'www.google.com',
        'www.youtube.com',
        'www.facebook.com',
        'api.twitter.com',
    ]

    seq_base = 1000

    # Generate TLS connections (each = 4 packets: SYN, SYN-ACK, ACK, TLS ClientHello)
    for i in range(num_tls):
        dst_ip, sni, dst_port = tls_connections[i % len(tls_connections)]
        src_port = random.randint(49152, 65535)

        eth = create_ethernet_header(user_mac, gateway_mac)
        tcp = create_tcp_header(src_port, dst_port, seq_base, 0, 0x02)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)

        tcp = create_tcp_header(dst_port, src_port, seq_base + 1000, seq_base + 1, 0x12)
        ip = create_ip_header(dst_ip, user_ip, 6, len(tcp))
        eth = create_ethernet_header(gateway_mac, user_mac)
        writer.write_packet(eth + ip + tcp)

        eth = create_ethernet_header(user_mac, gateway_mac)
        tcp = create_tcp_header(src_port, dst_port, seq_base + 1, seq_base + 1001, 0x10)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)

        tls_data = create_tls_client_hello(sni)
        tcp = create_tcp_header(src_port, dst_port, seq_base + 1, seq_base + 1001, 0x18)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(tls_data))
        writer.write_packet(eth + ip + tcp + tls_data)

        seq_base += 10000

    # Generate HTTP connections (each = 2 packets: SYN, HTTP request)
    for i in range(num_http):
        dst_ip, host, dst_port = http_connections[i % len(http_connections)]
        src_port = random.randint(49152, 65535)

        eth = create_ethernet_header(user_mac, gateway_mac)
        tcp = create_tcp_header(src_port, dst_port, seq_base, 0, 0x02)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)

        http_data = create_http_request(host)
        tcp = create_tcp_header(src_port, dst_port, seq_base + 1, 1, 0x18)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(http_data))
        writer.write_packet(eth + ip + tcp + http_data)

        seq_base += 10000

    # Generate DNS queries
    dns_server = '8.8.8.8'
    for i in range(num_dns):
        domain = dns_queries[i % len(dns_queries)]
        src_port = random.randint(49152, 65535)

        dns_data = create_dns_query(domain)
        eth = create_ethernet_header(user_mac, gateway_mac)
        udp = create_udp_header(src_port, 53, len(dns_data))
        ip = create_ip_header(user_ip, dns_server, 17, len(udp) + len(dns_data))
        writer.write_packet(eth + ip + udp + dns_data)

    # Generate blocked IP traffic
    blocked_source_ip = '192.168.1.50'
    for i in range(num_blocked):
        src_port = random.randint(49152, 65535)
        dst_ip = '172.217.0.100'

        eth = create_ethernet_header('00:11:22:33:44:56', gateway_mac)
        tcp = create_tcp_header(src_port, 443, seq_base, 0, 0x02)
        ip = create_ip_header(blocked_source_ip, dst_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)

        seq_base += 1000

    writer.close()
    total_packets = num_tls * 4 + num_http * 2 + num_dns + num_blocked
    return total_packets


def count_pcap_packets(filename):
    """Count classic-PCAP records and reject malformed/truncated output."""
    with open(filename, "rb") as f:
        header = f.read(24)
        if len(header) != 24:
            raise ValueError(f"{filename}: missing/truncated PCAP global header")
        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian = ">"
        else:
            raise ValueError(f"{filename}: unrecognized PCAP magic {magic.hex()}")
        count = 0
        while True:
            packet_header = f.read(16)
            if not packet_header:
                return count
            if len(packet_header) != 16:
                raise ValueError(f"{filename}: truncated packet header")
            _, _, incl_len, _ = struct.unpack(endian + "IIII", packet_header)
            if len(f.read(incl_len)) != incl_len:
                raise ValueError(f"{filename}: truncated packet payload")
            count += 1


def run_benchmark(analyzer_path, pcap_path, config_name, num_runs=3,
                  lbs=1, fps=1, expected_output_packets=None):
    """Benchmark identical DPI work with different worker configurations."""
    times = []
    output_counts = []
    for i in range(num_runs):
        output_pcap = os.path.join(os.path.dirname(os.path.abspath(pcap_path)),
                                   f"bench_out_{config_name}_{i}.pcap")
        cmd = [analyzer_path, pcap_path, output_pcap,
               "--block-ip", "192.168.1.50",
               "--lbs", str(lbs), "--fps", str(fps)]
        start = time.perf_counter()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            print(f"  Run {i + 1}: TIMEOUT after 60 seconds; command: {cmd}")
            return None
        elapsed = time.perf_counter() - start
        if result.returncode != 0:
            print(f"  Run {i + 1}: FAILED (exit {result.returncode})")
            if result.stdout:
                print(f"  stdout (last 1500 chars):\n{result.stdout[-1500:]}")
            if result.stderr:
                print(f"  stderr (last 1500 chars):\n{result.stderr[-1500:]}")
            return None
        if not os.path.exists(output_pcap):
            print(f"  Run {i + 1}: FAILED (output PCAP not created)")
            return None
        try:
            packet_count = count_pcap_packets(output_pcap)
        except (OSError, ValueError) as exc:
            print(f"  Run {i + 1}: FAILED (invalid output PCAP: {exc})")
            return None
        if expected_output_packets is not None and packet_count != expected_output_packets:
            print(f"  Run {i + 1}: FAILED (output has {packet_count} packets; expected {expected_output_packets})")
            return None
        times.append(elapsed)
        output_counts.append(packet_count)
    return {
        "mean": statistics.mean(times),
        "stdev": statistics.stdev(times) if len(times) > 1 else 0,
        "min": min(times),
        "max": max(times),
        "runs": times,
        "output_packets": output_counts[0],
    }


def main():
    repo_root = os.path.dirname(os.path.abspath(__file__))
    executable_name = "dpi_engine.exe" if os.name == "nt" else "dpi_engine"
    configured_engine = os.environ.get("DPI_ENGINE_PATH")
    dpi_engine = os.path.abspath(configured_engine) if configured_engine else os.path.join(repo_root, "build", executable_name)
    if not os.path.exists(dpi_engine):
        print(f"ERROR: DPI engine executable not found: {dpi_engine}. Build first or set DPI_ENGINE_PATH.")
        return 1

    test_sizes = [
        ("small", 10, 5, 5, 2),
        ("medium", 50, 10, 10, 5),
        ("large", 200, 20, 20, 10),
        ("xlarge", 500, 50, 50, 25),
    ]
    num_runs = 3
    print("=" * 70)
    print("DPI ENGINE WORKER-SCALING BENCHMARK")
    print("=" * 70)
    print(f"Engine: {dpi_engine}")
    print("Same engine, same input, same filtering rules; only worker counts differ.")
    print("Baseline: 1 load balancer / 1 fast-path worker")
    print("Parallel: 2 load balancers / 2 fast-path workers")

    for size_name, tls, http, dns, blocked in test_sizes:
        pcap_name = os.path.join(repo_root, f"bench_{size_name}.pcap")
        print(f"\n{'=' * 70}\nBENCHMARK: {size_name.upper()}\n{'=' * 70}")
        expected_input_packets = generate_pcap(pcap_name, tls, http, dns, blocked)
        actual_input_packets = count_pcap_packets(pcap_name)
        if actual_input_packets != expected_input_packets:
            print(f"ERROR: generator reported {expected_input_packets}, file contains {actual_input_packets} packets")
            return 1
        print(f"Input: {actual_input_packets} packets, {os.path.getsize(pcap_name) / 1024:.1f} KB")

        # The generator adds exactly `blocked` packets from this source IP.
        expected_output_packets = actual_input_packets - blocked
        results = []
        for label, lbs, fps in (("Baseline (1 LB, 1 FP)", 1, 1),
                                ("Parallel (2 LBs, 2 FPs)", 2, 2)):
            print(f"\n  {label}:")
            result = run_benchmark(
                dpi_engine, pcap_name, f"{size_name}_{lbs}_{fps}", num_runs=num_runs,
                lbs=lbs, fps=fps, expected_output_packets=expected_output_packets)
            results.append(result)
            if result:
                pps = actual_input_packets / result["mean"] if result["mean"] > 0 else 0
                print(f"    Output PCAP: {result['output_packets']} packets (expected {expected_output_packets})")
                print(f"    Mean: {result['mean'] * 1000:.2f} ms ({pps:.0f} input packets/sec)")
                print(f"    Min/Max: {result['min'] * 1000:.2f} / {result['max'] * 1000:.2f} ms")
                print(f"    StDev: {result['stdev'] * 1000:.2f} ms")
            else:
                print("    FAILED — comparison for this size is invalid")

        if all(results):
            baseline_mean, parallel_mean = results[0]["mean"], results[1]["mean"]
            if parallel_mean > 0:
                print(f"\n  Relative speed ratio: {baseline_mean / parallel_mean:.2f}x (above 1 means parallel was faster)")
        else:
            print("\n  No speed comparison reported because at least one configuration failed.")

        for lbs, fps in ((1, 1), (2, 2)):
            for i in range(num_runs):
                output_pcap = os.path.join(repo_root, f"bench_out_{size_name}_{lbs}_{fps}_{i}.pcap")
                if os.path.exists(output_pcap):
                    os.remove(output_pcap)
        if os.path.exists(pcap_name):
            os.remove(pcap_name)

    print("\n" + "=" * 70)
    print("BENCHMARK COMPLETE")
    print("Note: this compares worker configurations, not a truly single-threaded implementation.")
    print("=" * 70)
    return 0


if __name__ == '__main__':
    main()