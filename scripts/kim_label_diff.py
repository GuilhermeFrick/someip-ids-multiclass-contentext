import os, sys, collections
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from kim_label_rule import ORDEM, meta  # noqa: E402
OUT = "/work/kimf"
ben = np.load(os.path.join(OUT, "benign_traffic.pcap.npz"))
bmac = {bytes(x) for x in ben["mac"]}
for f in ORDEM[:4]:
    d = np.load(os.path.join(OUT, f + ".npz")); n = len(d["X"])
    kim = np.zeros(n, bool); kim[np.load(os.path.join(OUT, f + ".kim_attack_idx.npy"))] = True
    macl = np.array([bytes(x) not in bmac for x in d["mac"]])
    M = meta(os.path.join("/d", f))
    print("=====", f)
    for nome, sel in (("Kim=ataque, MAC=normal", kim & ~macl), ("Kim=normal, MAC=ataque", ~kim & macl)):
        c = collections.Counter(M[k] [:3] + (M[k][3] if M[k][3] < 40000 else 'eph', M[k][4] if M[k][4] < 40000 else 'eph') for k in np.flatnonzero(sel))
        print("  %s: %d" % (nome, sel.sum()))
        for k, v in c.most_common(10): print("      ", k, v)
    # mesmo fluxo, rotulos diferentes: quando o Kim muda de ideia no tempo?
    k_idx = np.flatnonzero(kim & ~macl)
    if len(k_idx):
        print("  primeira/ultima posicao dos extras:", k_idx[0], k_idx[-1], "de", n)
    k2 = np.flatnonzero(~kim & macl)
    if len(k2):
        print("  primeira/ultima posicao dos excluidos:", k2[0], k2[-1], "de", n)
