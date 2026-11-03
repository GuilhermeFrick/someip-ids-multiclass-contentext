"""Figura de domínio (t-SNE) + mistura por vizinhos no espaço original, com sorteios repetidos."""
import json, sys
import numpy as np
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.manifold import TSNE
from sklearn.neighbors import NearestNeighbors

z = np.load(sys.argv[1]); X, g = z["X"], z["g"]
KIM, P1, P2, P3, PK = "normal", "bancada própria, conjunto 1", "bancada própria, conjunto 2", "bancada própria, conjunto 3", "bancada, payload do Kim"
COR = {"kim": "#8c8c8c", "propria": "#E69F00", "pk": "#0072B2"}
ROT = {"kim": "Kim, benigno", "propria": "bancada, conteúdo próprio (3 conjuntos)", "pk": "bancada, payload do Kim"}

def amostra(rng, n):
    idx = {"kim": rng.choice(np.flatnonzero(g == KIM), n, replace=False),
           "pk": rng.choice(np.flatnonzero(g == PK), n, replace=False),
           "propria": np.concatenate([rng.choice(np.flatnonzero(g == p), n // 3, replace=False) for p in (P1, P2, P3)])}
    return idx

def mistura(ia, ib, nf, k=10):
    M = np.vstack([X[ia, :nf], X[ib, :nf]]); lab = np.r_[np.zeros(len(ia)), np.ones(len(ib))]
    _, I = NearestNeighbors(n_neighbors=k + 1).fit(M).kneighbors(M)
    return float((lab[I[:, 1:]] != lab[:, None]).mean())

# 1) mistura: 5 sorteios de 3000 por grupo
pares = {"Kim × bancada própria, conj. 1": (KIM, P1), "Kim × bancada própria, conj. 2": (KIM, P2),
         "Kim × bancada própria, conj. 3": (KIM, P3), "Kim × bancada com payload do Kim": (KIM, PK),
         "controle: bancada conj. 1 × conj. 2": (P1, P2), "controle: Kim × Kim (metades)": None}
res = {}
for nf in (12, 16):
    for nome, par in pares.items():
        v = []
        for s in range(5):
            rng = np.random.default_rng(100 + s)
            if par is None:
                i = rng.choice(np.flatnonzero(g == KIM), 6000, replace=False); a, b = i[:3000], i[3000:]
            else:
                a = rng.choice(np.flatnonzero(g == par[0]), 3000, replace=False)
                b = rng.choice(np.flatnonzero(g == par[1]), 3000, replace=False)
            v.append(mistura(a, b, nf))
        res[f"{nf}|{nome}"] = (float(np.mean(v)), float(np.std(v)))
        print(f"{nf:2d}  {nome:38s} {np.mean(v):.3f} ± {np.std(v):.3f}", flush=True)
json.dump(res, open("mistura.json", "w"), indent=1, ensure_ascii=False)

# 2) t-SNE: 4 sementes (sorteio + inicialização), 12 features
def painel(ax, seed, nf=12, n=3000):
    idx = amostra(np.random.default_rng(seed), n)
    ordem = ["propria", "pk", "kim"]
    M = np.vstack([X[idx[k], :nf] for k in ordem])
    Y = TSNE(2, perplexity=30, init="pca", random_state=seed).fit_transform(M)
    o = 0
    for k in ordem:
        m = len(idx[k]); ax.scatter(Y[o:o + m, 0], Y[o:o + m, 1], s=2.5, c=COR[k], label=ROT[k], alpha=.75, linewidths=0); o += m
    ax.set_xticks([]); ax.set_yticks([])
    for sp in ax.spines.values(): sp.set_color("#d0d0d0")

fig, ax = plt.subplots(figsize=(7.5, 7))
painel(ax, 0)
ax.legend(markerscale=5, fontsize=9, frameon=False, loc="lower left")
ax.set_title("Tráfego benigno no espaço das 12 features do Kim (t-SNE)", fontsize=11)
fig.tight_layout(); fig.savefig("tsne_dominio.png", dpi=150)

fig, ax = plt.subplots(2, 2, figsize=(10, 10))
for a, s in zip(ax.flat, (1, 2, 3, 4)):
    painel(a, s); a.set_title(f"semente {s}", fontsize=10)
ax[0, 0].legend(markerscale=5, fontsize=8, frameon=False, loc="lower left")
fig.suptitle("Robustez: 4 sorteios e inicializações do t-SNE", fontsize=11)
fig.tight_layout(); fig.savefig("tsne_dominio_sementes.png", dpi=110)
print("ok")
