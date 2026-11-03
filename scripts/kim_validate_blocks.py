"""Casa os blocos de ataque e de fundo normal dos .npy do Kim com os PCAPs de ataque.

Pressupõe os caches de scripts/kim_validate.py. Testa a regra de rótulo (IP de origem ausente
do benigno; MAC de origem ausente do benigno) e a ordem dos arquivos, intercalando treino e
teste (pares/ímpares) dentro de cada bloco, como no bloco benigno.
"""
import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import kim_faithful as kf  # noqa: E402
from kim_validate import FILES  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--npy", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    mm = np.load(os.path.join(a.out, "minmax.npz"))
    data = {f: np.load(os.path.join(a.out, f + ".npz")) for f in FILES}
    ben = data[FILES[0]]
    bip = {bytes(x) for x in ben["ip"]}
    bmac = {bytes(x) for x in ben["mac"]}
    Xtr = np.load(os.path.join(a.npy, "X_train.npy"), mmap_mode="r")
    Xte = np.load(os.path.join(a.npy, "X_test.npy"), mmap_mode="r")
    nb_tr, nb_te = (len(ben["X"]) + 1) // 2, len(ben["X"]) // 2
    na = 831159
    atk = np.empty((2 * na, 12))
    atk[0::2] = Xtr[nb_tr:nb_tr + na]
    atk[1::2] = Xte[nb_te:nb_te + na]
    print("bloco de ataque do Kim, intercalado:", atk.shape)
    for regra in ("ip", "mac"):
        tot = 0
        offs = {}
        for f in FILES[1:]:
            d = data[f]
            if regra == "ip":
                lab = np.array([bytes(x) not in bip for x in d["ip"]])
            else:
                lab = np.array([bytes(x) not in bmac for x in d["mac"]])
            A = kf.normalize(d["X"][lab], mm["lo"], mm["hi"])
            tot += len(A)
            # onde a primeira linha de ataque deste arquivo aparece no bloco do Kim
            hit = np.flatnonzero(np.abs(atk - A[0]).max(1) < 1e-6)
            offs[f] = (len(A), hit[:3])
        print("regra %s: total de ataques %d (Kim 1662318)" % (regra, tot))
        for f, (n, h) in offs.items():
            print("   %-36s %8d ataques   1a linha no bloco do Kim em %s" % (f, n, h))


if __name__ == "__main__":
    main()
