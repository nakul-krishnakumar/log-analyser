"""Stage 1: pcap(.bz2) -> Wireshark-style packet log CSV on stdout.

Same columns as Wireshark's "Export Packet Dissections -> As CSV" with absolute UTC time:
  "No.","Time","Source","Destination","Protocol","Length","Info"
Stdlib only (tshark is the drop-in alternative where Wireshark is installed). Handles
CTU-13's header-truncated captures: Length is the original wire length, Len= the original payload size.
"""
import bz2
import datetime as dt
import socket
import struct
import sys

TCP_FLAGS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]
ICMP_INFO = {0: "Echo (ping) reply", 3: "Destination unreachable", 8: "Echo (ping) request", 11: "Time-to-live exceeded"}
ETHER = {0x0806: "ARP", 0x86DD: "IPv6"}


def info_and_proto(frame):
    """Returns (src, dst, protocol, info) for one Ethernet frame (captured bytes only)."""
    etype, off = struct.unpack_from("!H", frame, 12)[0], 14
    if etype == 0x8100 and len(frame) >= 18:  # 802.1Q VLAN tag
        etype, off = struct.unpack_from("!H", frame, 16)[0], 18
    mac = lambda b: ":".join(f"{x:02x}" for x in b)
    if etype != 0x0800 or len(frame) < off + 20:
        return mac(frame[6:12]), mac(frame[0:6]), ETHER.get(etype, f"0x{etype:04x}"), ""
    ihl = (frame[off] & 0x0F) * 4
    ip_len, proto = struct.unpack_from("!H", frame, off + 2)[0], frame[off + 9]
    src, dst = socket.inet_ntoa(frame[off + 12:off + 16]), socket.inet_ntoa(frame[off + 16:off + 20])
    l4 = off + ihl
    if proto == 6 and len(frame) >= l4 + 16:
        sp, dp, seq, ack, off_flags, win = struct.unpack_from("!HHIIHH", frame, l4)
        flags = ", ".join(n for bit, n in TCP_FLAGS if off_flags & bit)
        payload = max(ip_len - ihl - ((off_flags >> 12) * 4), 0)
        return src, dst, "TCP", f"{sp} → {dp} [{flags}] Seq={seq} Ack={ack} Win={win} Len={payload}"
    if proto == 17 and len(frame) >= l4 + 8:
        sp, dp, ulen = struct.unpack_from("!HHH", frame, l4)
        return src, dst, "UDP", f"{sp} → {dp} Len={max(ulen - 8, 0)}"
    if proto == 1 and len(frame) >= l4 + 2:
        t, c = frame[l4], frame[l4 + 1]
        return src, dst, "ICMP", ICMP_INFO.get(t, f"Type={t} Code={c}")
    return src, dst, "IPv4", f"IP protocol {proto}"


def pcapng_packets(f):
    e, tsres = "<", []
    while len(head := f.read(8)) == 8:
        if head[:4] == b"\x0a\x0d\x0d\x0a":  # section header: byte-order magic decides endianness
            bom = f.read(4)
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            f.read(struct.unpack(e + "I", head[4:])[0] - 12)
            tsres = []
            continue
        btype, blen = struct.unpack(e + "II", head)
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return  # capture ended mid-block
        if btype == 1:  # interface description: linktype + optional if_tsresol (default microseconds)
            assert struct.unpack_from(e + "H", body)[0] == 1, "only Ethernet captures are supported"
            res, pos = 1e-6, 8
            while pos + 4 <= len(body) - 4:
                code, olen = struct.unpack_from(e + "HH", body, pos)
                if code == 0:
                    break
                if code == 9:
                    v = body[pos + 4]
                    res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                pos += 4 + (olen + 3) // 4 * 4
            tsres.append(res)
        elif btype == 6:  # enhanced packet
            iface, hi, lo, cap, orig = struct.unpack_from(e + "IIIII", body)
            yield ((hi << 32) | lo) * tsres[iface], orig, body[20:20 + cap]


def packets(f):
    if f.peek(4)[:4] == b"\x0a\x0d\x0d\x0a":
        yield from pcapng_packets(f)
        return
    magic = f.read(24)[:4]
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}[magic]
    nanos = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    rec = struct.Struct(endian + "IIII")
    while hdr := f.read(16):
        if len(hdr) < 16:
            return  # capture ended mid-record
        sec, frac, incl, orig = rec.unpack(hdr)
        yield sec + frac / (1e9 if nanos else 1e6), orig, f.read(incl)


def main(path):
    out = sys.stdout
    out.write('"No.","Time","Source","Destination","Protocol","Length","Info"\n')
    opener = bz2.open if path.endswith(".bz2") else (lambda p, m: open(p, m, buffering=1 << 20))
    with opener(path, "rb") as f:
        for no, (ts, orig, frame) in enumerate(packets(f), 1):
            src, dst, proto, info = info_and_proto(frame) if len(frame) >= 14 else ("", "", "Malformed", "")
            t = dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
            out.write(f'"{no}","{t}","{src}","{dst}","{proto}","{orig}","{info}"\n')


if __name__ == "__main__":
    main(sys.argv[1])
