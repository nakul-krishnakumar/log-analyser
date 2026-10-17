"""Stage 1: pcap / pcapng (optionally .gz/.bz2) -> Wireshark-style packet log CSV on stdout.

Same columns as Wireshark's "Export Packet Dissections -> As CSV" with absolute UTC time:
  "No.","Time","Source","Destination","Protocol","Length","Info"
Stdlib only (tshark is the drop-in alternative where Wireshark is installed). Handles
CTU-13's header-truncated captures: Length is the original wire length, Len= the original payload size.
Link types: Ethernet, Linux cooked (SLL/SLL2, Wireshark's "any" interface), raw IP, BSD loopback.
"""
import bz2
import gzip
import datetime as dt
import socket
import struct
import sys

TCP_FLAGS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]
ICMP_INFO = {0: "Echo (ping) reply", 3: "Destination unreachable", 8: "Echo (ping) request", 11: "Time-to-live exceeded"}
ETHER = {0x0806: "ARP", 0x86DD: "IPv6"}


def network_layer(frame, linktype):
    """(ethertype, offset of the network header, (src, dst) labels for non-IP frames) for one link-layer frame."""
    if linktype == 1:  # Ethernet
        etype, off = struct.unpack_from("!H", frame, 12)[0], 14
        if etype == 0x8100:  # 802.1Q VLAN tag
            etype, off = struct.unpack_from("!H", frame, 16)[0], 18
        mac = lambda b: ":".join(f"{x:02x}" for x in b)
        return etype, off, (mac(frame[6:12]), mac(frame[0:6]))
    if linktype == 113:  # Linux cooked capture v1
        return struct.unpack_from("!H", frame, 14)[0], 16, ("", "")
    if linktype == 276:  # Linux cooked capture v2
        return struct.unpack_from("!H", frame, 0)[0], 20, ("", "")
    if linktype in (12, 101, 228, 229):  # raw IP
        return (0x0800 if frame[0] >> 4 == 4 else 0x86DD), 0, ("", "")
    if linktype == 0:  # BSD loopback: 4-byte address family in host order
        return (0x0800 if 2 in (frame[0], frame[3]) else 0x86DD), 4, ("", "")
    raise ValueError(f"unsupported link type {linktype} (supported: Ethernet, Linux cooked, raw IP, loopback)")


def info_and_proto(frame, linktype=1):
    """Returns (src, dst, protocol, info) for one captured frame (captured bytes only)."""
    try:
        etype, off, l2 = network_layer(frame, linktype)
    except (struct.error, IndexError):
        return "", "", "Malformed", ""
    if etype != 0x0800 or len(frame) < off + 20:
        return *l2, ETHER.get(etype, f"0x{etype:04x}"), ""
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
    e, ifaces = "<", []  # per interface: (timestamp resolution, link type)
    while len(head := f.read(8)) == 8:
        if head[:4] == b"\x0a\x0d\x0d\x0a":  # section header: byte-order magic decides endianness
            bom = f.read(4)
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            f.read(struct.unpack(e + "I", head[4:])[0] - 12)
            ifaces = []
            continue
        btype, blen = struct.unpack(e + "II", head)
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return  # capture ended mid-block
        if btype == 1:  # interface description: linktype + optional if_tsresol (default microseconds)
            linktype, res, pos = struct.unpack_from(e + "H", body)[0], 1e-6, 8
            while pos + 4 <= len(body) - 4:
                code, olen = struct.unpack_from(e + "HH", body, pos)
                if code == 0:
                    break
                if code == 9:
                    v = body[pos + 4]
                    res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                pos += 4 + (olen + 3) // 4 * 4
            ifaces.append((res, linktype))
        elif btype == 6:  # enhanced packet
            iface, hi, lo, cap, orig = struct.unpack_from(e + "IIIII", body)
            res, linktype = ifaces[iface]
            yield ((hi << 32) | lo) * res, orig, linktype, body[20:20 + cap]


def packets(f):
    if f.peek(4)[:4] == b"\x0a\x0d\x0d\x0a":
        yield from pcapng_packets(f)
        return
    header = f.read(24)
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(header[:4])
    if endian is None:
        raise ValueError("not a pcap or pcapng capture file")
    nanos = header[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack_from(endian + "I", header, 20)[0] & 0xFFFF
    rec = struct.Struct(endian + "IIII")
    while hdr := f.read(16):
        if len(hdr) < 16:
            return  # capture ended mid-record
        sec, frac, incl, orig = rec.unpack(hdr)
        yield sec + frac / (1e9 if nanos else 1e6), orig, linktype, f.read(incl)


def main(path):
    out = sys.stdout
    out.write('"No.","Time","Source","Destination","Protocol","Length","Info"\n')
    opener = {".bz2": bz2.open, ".gz": gzip.open}.get(path[path.rfind("."):], lambda p, m: open(p, m, buffering=1 << 20))
    with opener(path, "rb") as f:
        for no, (ts, orig, linktype, frame) in enumerate(packets(f), 1):
            src, dst, proto, info = info_and_proto(frame, linktype)
            t = dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
            out.write(f'"{no}","{t}","{src}","{dst}","{proto}","{orig}","{info}"\n')


if __name__ == "__main__":
    main(sys.argv[1])
