import struct
import sys

def check_pcap(filepath):
    print(f"Checking {filepath}:")
    with open(filepath, 'rb') as f:
        d = f.read()
    magic = struct.unpack('<I', d[0:4])[0]
    v_maj, v_min = struct.unpack('<HH', d[4:8])
    snaplen, linktype = struct.unpack('<II', d[16:24])
    print(f"  Magic: 0x{magic:08x}")
    print(f"  Version: {v_maj}.{v_min}")
    print(f"  Snaplen: {snaplen}, LinkType: {linktype}")
    
    n = 0
    o = 24
    while o + 16 <= len(d):
        ts_sec, ts_usec, incl, orig = struct.unpack('<IIII', d[o:o+16])
        o += 16 + incl
        n += 1
    print(f"  Records: {n}")
    print(f"  Total file bytes: {len(d)}")

if __name__ == '__main__':
    for arg in sys.argv[1:]:
        check_pcap(arg)
