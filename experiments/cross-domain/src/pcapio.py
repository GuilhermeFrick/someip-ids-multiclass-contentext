"""Leitura rápida de PCAP (libpcap clássico, microssegundos, little-endian).
Equivalente a scapy RawPcapReader + extract._ts da C1: ts = sec + usec*1e-6."""
import struct

def ler(path):
    with open(path, "rb", buffering=1 << 22) as f:
        cab = f.read(24)
        if cab[:4] != b"\xd4\xc3\xb2\xa1":
            raise ValueError("formato não suportado: %r" % cab[:4])
        rd = f.read
        un = struct.Struct("<IIII").unpack
        while True:
            h = rd(16)
            if len(h) < 16:
                return
            sec, usec, incl, _orig = un(h)
            raw = rd(incl)
            if len(raw) < incl:
                return
            yield sec + usec * 1e-6, raw
