import os, sys
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import kim_faithful as kf  # noqa: E402
from kim_label_rule import ORDEM  # noqa: E402
OUT, NPY = "/work/kimf", "/k"
mm = np.load(os.path.join(OUT, "minmax.npz"))
Ktr = np.load(os.path.join(NPY, "X_train.npy"), mmap_mode="r"); Kte = np.load(os.path.join(NPY, "X_test.npy"), mmap_mode="r")
g0 = 2193801 + 1662318            # índice global do início do bloco normal
n = 14233347 - g0
blk = np.empty((n, 12), np.float32)
# índice global g -> treino se g par (g//2), teste se ímpar (g//2)
gi = np.arange(g0, g0 + n)
blk[gi % 2 == 0] = Ktr[gi[gi % 2 == 0] // 2]
blk[gi % 2 == 1] = Kte[gi[gi % 2 == 1] // 2]
for f in ORDEM:
    X = kf.normalize(np.load(os.path.join(OUT, f + ".npz"))["X"], mm["lo"], mm["hi"]).astype(np.float32)
    lab = np.zeros(len(X), bool); lab[np.load(os.path.join(OUT, f + ".kim_attack_idx.npy"))] = True
    N = X[~lab]
    hits = [np.flatnonzero(np.abs(blk[:]-N[k]).max(1) < 2e-6)[:3] for k in (0, 1, 2)]
    print("%-36s normais %8d  1as linhas no bloco do Kim em %s" % (f, len(N), hits))
