import sys, os, collections
sys.path.insert(0, os.path.dirname(__file__))
from pcapio import ler
d = sys.argv[1]
for f in sorted(os.listdir(d)):
    c = collections.Counter()
    for ts, raw in ler(os.path.join(d, f)):
        if raw[12:14] != b"\x08\x00": continue
        c[(".".join(map(str, raw[26:30])), raw[6:12].hex(":"))] += 1
    print(f)
    for (ip, mac), n in sorted(c.items()):
        print("   %-15s %s %9d" % (ip, mac, n))
