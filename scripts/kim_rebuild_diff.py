import os, numpy as np, collections
OUT, NPY = "/work/kimf", "/k"
R = np.load(os.path.join(OUT, "kim_rebuilt.npz"))
K = np.load(os.path.join(NPY, "X_train.npy"))
d = np.abs(R["Xtr"].astype(np.float64) - K)
bad = np.flatnonzero(d.max(1) > 1e-6)
g = bad * 2                      # índice global (treino = pares)
blocos = [(0, 2193801, "benigno"), (2193801, 2193801 + 1662318, "ataque"), (2193801 + 1662318, 14233347, "normal")]
for a, b, n in blocos:
    m = (g >= a) & (g < b); print(n, int(m.sum()))
print("primeiros índices globais ruins:", g[:20])
print("colunas mais afetadas:", collections.Counter(int(np.argmax(d[i])) for i in bad).most_common(12))
# as linhas ruins casam com alguma linha nossa vizinha? (troca de ordem)
for i in bad[:5]:
    j = np.flatnonzero(np.abs(R["Xtr"][max(0, i - 50):i + 50].astype(np.float64) - K[i]).max(1) < 1e-6)
    print("linha", i, "do Kim casa com nossa linha", (j + max(0, i - 50)).tolist())
