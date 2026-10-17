"""Converter checks on hand-built captures: classic pcap (Ethernet) and gzipped pcapng (Linux cooked v2).

    uv run python tests/test_ingest.py
"""
import gzip
import io
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "ingest/pcap_to_csv.py"


def ipv4(proto, l4, total):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0,
                       socket.inet_aton("10.0.0.1"), socket.inet_aton("8.8.8.8")) + l4


tcp_syn = ipv4(6, struct.pack("!HHIIHHHH", 1078, 80, 7, 0, (5 << 12) | 0x02, 65535, 0, 0), 40)
udp_dns = ipv4(17, struct.pack("!HHHH", 51180, 53, 8 + 31, 0), 20 + 8 + 31)  # 31-byte payload, header-truncated
eth = b"\x00" * 12 + b"\x08\x00" + tcp_syn
sll2 = struct.pack("!HHIHBB8s", 0x0800, 0, 2, 1, 0, 6, b"\x00" * 8) + udp_dns

pcap = (struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1313675975, 87798, len(eth), 60) + eth)


def block(btype, body):
    body += b"\x00" * (-len(body) % 4)
    return struct.pack("<II", btype, len(body) + 12) + body + struct.pack("<I", len(body) + 12)


ts = 1313675975_087798  # microseconds
pcapng = (block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
          + block(1, struct.pack("<HHI", 276, 0, 65535))
          + block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(sll2), len(sll2) + 31) + sll2))


def convert(name, data):
    with tempfile.TemporaryDirectory() as d:
        path = pathlib.Path(d) / name
        path.write_bytes(data)
        r = subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True)
        return r.returncode, r.stdout.splitlines(), r.stderr


code, rows, _ = convert("a.pcap", pcap)
assert code == 0 and rows[0] == '"No.","Time","Source","Destination","Protocol","Length","Info"', rows
assert rows[1] == '"1","2011-08-18 13:59:35.087798","10.0.0.1","8.8.8.8","TCP","60","1078 → 80 [SYN] Seq=7 Ack=0 Win=65535 Len=0"', rows[1]
print("ok   classic pcap, Ethernet, TCP SYN")

code, rows, _ = convert("b.pcapng.gz", gzip.compress(pcapng))
assert code == 0 and rows[1] == '"1","2011-08-18 13:59:35.087798","10.0.0.1","8.8.8.8","UDP","79","51180 → 53 Len=31"', rows
print("ok   gzipped pcapng, Linux cooked v2, UDP")

code, rows, err = convert("c.pcap", b"this is not a capture file")
assert code != 0 and "not a pcap or pcapng capture file" in err, err
print("ok   non-capture file fails with a clear message")
