"""Amostra para a figura de domínio: 10 mil pacotes benignos do Kim e de cada rodada benigna da bancada, 12 fiéis + 4 da C1.

Roda no runner (someip-parity:1), com /work = ~/work, /tb = someip-testbench, /d = PCAPs do Kim.
"""
import os, sys
import numpy as np
sys.path.insert(0, "/work/someip-ids-multiclass-contentext/src")
sys.path.insert(0, "/work/someip-ids-multiclass-contentext/scripts")
import kim_faithful as kf
from kim_validate import FILES
from kim_multiclass import FAMILIA, CLASSES
from kim_c1_multiclass import c1_extra

N = 10000
rng = np.random.default_rng(0)
out = "/work/kimf"
mm = np.load(os.path.join(out, "minmax.npz")); lo, hi = mm["lo"], mm["hi"]
# arquivo por arquivo, para não carregar o dataset inteiro (o runner está com o exp3 na memória)
por_classe = {c: [] for c in range(5)}
elo = np.full(4, np.inf); ehi = np.full(4, -np.inf)
for f in FILES:
    Xf = np.load(os.path.join(out, f + ".npz"))["X"]; Ef = np.load(os.path.join(out, f + ".c1ext.npy"))
    elo = np.minimum(elo, Ef.min(0)); ehi = np.maximum(ehi, Ef.max(0))
    yy = np.zeros(len(Xf), np.int64)
    if f in FAMILIA:
        yy[np.load(os.path.join(out, f + ".kim_attack_idx.npy"))] = FAMILIA[f]
    for c in (0,):
        idx = np.flatnonzero(yy == c)
        if len(idx):
            k = rng.choice(idx, min(N, len(idx)), replace=False)
            por_classe[c].append((len(idx), Xf[k], Ef[k]))
    del Xf, Ef, yy
rows, grupos = [], []
for c, partes in [(0, por_classe[0])]:
    tot = sum(p[0] for p in partes)
    Xc = np.concatenate([p[1] for p in partes]); Ec = np.concatenate([p[2] for p in partes])
    w = np.concatenate([np.full(len(p[1]), p[0] / len(p[1])) for p in partes])
    s = rng.choice(len(Xc), N, replace=False, p=w / w.sum())   # peso = tamanho do arquivo na classe
    rows.append(np.hstack([kf.normalize(Xc[s], lo, hi), (Ec[s] - elo) / np.where(ehi > elo, ehi - elo, 1)]))
    grupos += [CLASSES[c]] * N
A = np.vstack(rows)
models = kf.fit_models("/d/benign_traffic.pcap")
for nome, p in (("bancada própria, conjunto 1", "/tb/experiments/bench-train/runs/teste-none/scn.pcap"),
                ("bancada própria, conjunto 2", "/tb/experiments/bench-train/runs/teste2-none/scn.pcap"),
                ("bancada própria, conjunto 3", "/tb/experiments/bench-train/runs/teste3-none/scn.pcap"),
                ("bancada, payload do Kim", "/tb/platform/scenario-live/out-none-dataset/scn.pcap")):
    Xb = kf.extract(p, models)[0]; Eb = c1_extra(p)
    s = rng.choice(len(Xb), N, replace=False)
    A = np.vstack([A, np.hstack([kf.normalize(Xb[s], lo, hi), (Eb[s] - elo) / np.where(ehi > elo, ehi - elo, 1)])])
    grupos += [nome] * N
np.savez("/work/kimf/tsne_dominio.npz", X=A.astype(np.float32), g=np.array(grupos))
print(A.shape, "ok")
