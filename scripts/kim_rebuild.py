"""Reconstrói X_train/X_test/y do Kim a partir dos PCAPs e compara com os .npy publicados.

Montagem recuperada: [benigno | ataques de cada arquivo | normais de cada arquivo], arquivos de
ataque na ordem ORDEM e de normais na ordem ORDEM_NORMAL, rótulo = conjunto de pacotes que o Kim marcou (kim_attack_idx.npy, de
scripts/kim_label_rule.py); split global par (treino) / ímpar (teste).
"""
import os, sys
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import kim_faithful as kf  # noqa: E402
from kim_label_rule import ORDEM  # noqa: E402
OUT, NPY = "/work/kimf", "/k"
mm = np.load(os.path.join(OUT, "minmax.npz"))
norm = lambda f: kf.normalize(np.load(os.path.join(OUT, f + ".npz"))["X"], mm["lo"], mm["hi"]).astype(np.float32)
partes_x, partes_y, origem = [norm("benign_traffic.pcap")], [], []
partes_y.append(np.zeros(len(partes_x[0]), np.int64))
# ordem dos arquivos no bloco de normais (recuperada por scripts/kim_normal_order.py)
ORDEM_NORMAL = ["fuzzy_sd_offer_rand_noti(2).pcap", "fuzzy_sd_offer_rand_noti(3).pcap",
                "fuzzy_sd_offer_rand_noti(1).pcap", "dos_noti_flood.pcap",
                "mitm_single_attacker.pcap", "mitm_multi_attacker.pcap"]
atk, nor = [], {}
for f in ORDEM:
    X = norm(f); lab = np.zeros(len(X), bool); lab[np.load(os.path.join(OUT, f + ".kim_attack_idx.npy"))] = True
    atk.append(X[lab]); nor[f] = X[~lab]
nor = [nor[f] for f in ORDEM_NORMAL]
partes_x += atk + nor
partes_y += [np.ones(len(a), np.int64) for a in atk] + [np.zeros(len(n), np.int64) for n in nor]
X = np.concatenate(partes_x); y = np.concatenate(partes_y)
Xtr, Xte, ytr, yte = X[0::2], X[1::2], y[0::2], y[1::2]
Ktr = np.load(os.path.join(NPY, "X_train.npy")); Kte = np.load(os.path.join(NPY, "X_test.npy"))
Ltr = np.load(os.path.join(NPY, "y_train.npy")); Lte = np.load(os.path.join(NPY, "y_test.npy"))
print("formas", Xtr.shape, Ktr.shape, Xte.shape, Kte.shape)
for nome, a, b, la, lb in (("treino", Xtr, Ktr, ytr, Ltr), ("teste", Xte, Kte, yte, Lte)):
    d = np.abs(a.astype(np.float64) - b.astype(np.float64))
    print(nome, "max|dif| por coluna:", " ".join("%.1e" % v for v in d.max(0)), "| rótulos iguais:", bool((la == lb).all()),
          "| linhas com dif>1e-6:", int((d.max(1) > 1e-6).sum()))
np.savez_compressed(os.path.join(OUT, "kim_rebuilt.npz"), Xtr=Xtr, Xte=Xte, ytr=ytr, yte=yte)
