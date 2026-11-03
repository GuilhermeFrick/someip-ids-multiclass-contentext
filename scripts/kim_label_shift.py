"""Testa se o rótulo do Kim é o de um pacote vizinho (deslocamento) ou outra regra simples."""
import os, sys
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from kim_label_rule import ORDEM  # noqa: E402
OUT = "/work/kimf"
ben = np.load(os.path.join(OUT, "benign_traffic.pcap.npz"))
bip = {bytes(x) for x in ben["ip"]}
bmac = {bytes(x) for x in ben["mac"]}
for f in ORDEM:
    d = np.load(os.path.join(OUT, f + ".npz"))
    n = len(d["X"])
    kim = np.zeros(n, bool); kim[np.load(os.path.join(OUT, f + ".kim_attack_idx.npy"))] = True
    ipl = np.array([bytes(x) not in bip for x in d["ip"]])
    macl = np.array([bytes(x) not in bmac for x in d["mac"]])
    res = []
    for nome, lab in (("ip", ipl), ("mac", macl)):
        for s in (-2, -1, 0, 1, 2):
            sh = np.roll(lab, s)
            res.append(((sh == kim).mean(), nome, s, (sh & ~kim).sum(), (~sh & kim).sum()))
    res.sort(reverse=True)
    print("%-36s Kim=%d" % (f, kim.sum()), " | ".join("%s%+d acerto=%.5f (+%d/-%d)" % (r[1], r[2], r[0], r[3], r[4]) for r in res[:3]))
