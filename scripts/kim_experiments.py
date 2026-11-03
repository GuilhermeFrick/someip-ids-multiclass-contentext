"""Experimentos 1 e 2 com o extrator fiel ao Kim (src/kim_faithful.py).

  exp1  : divisão do Kim (par/ímpar global), vetores reconstruídos dos PCAPs
          (scripts/kim_rebuild.py); deve reproduzir o artigo (ROC-AUC 0,99, PR-AUC 0,93).
  exp2a : divisão temporal por arquivo (primeiros 70% de cada PCAP no treino), mesmo
          extrator (modelo de bytes ajustado no benigno inteiro, como o Kim).
  exp2b : idem, mas o modelo de bytes é ajustado só nos primeiros 70% do benigno.

Rótulo = o do Kim (conjunto exato recuperado por scripts/kim_label_rule.py). XGBoost com
os hiperparâmetros da Tabela 2 do artigo, API nativa (a imagem não tem sklearn).
Limiares: 0,36 (o do Kim) e o de melhor F1 nas predições do próprio treino.

Uso (someip-parity:1):  python3 scripts/kim_experiments.py --pcap /d --out /work/kimf --exp exp1 exp2a exp2b
"""
import argparse
import json
import os
import sys
import time

import numpy as np
import xgboost as xgb

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import kim_faithful as kf  # noqa: E402
from kim_validate import FILES  # noqa: E402

PARAMS = dict(objective="binary:logistic", eta=0.05, max_depth=6, subsample=0.8,
              colsample_bytree=0.8, reg_lambda=1.0, gamma=0.0, min_child_weight=1,
              tree_method="hist", eval_metric="auc", seed=42, nthread=4)
N_TREES = 1000
FRAC = 0.7


def roc_auc(y, s):
    o = np.argsort(s, kind="mergesort")
    r = np.empty(len(s)); r[o] = np.arange(1, len(s) + 1)
    # empates: média dos postos
    ss = s[o]; i = 0
    while i < len(ss):
        j = i
        while j + 1 < len(ss) and ss[j + 1] == ss[i]:
            j += 1
        if j > i:
            r[o[i:j + 1]] = (i + j + 2) / 2.0
        i = j + 1
    p = y == 1
    return (r[p].sum() - p.sum() * (p.sum() + 1) / 2) / (p.sum() * (~p).sum())


def avg_precision(y, s):
    o = np.argsort(-s, kind="mergesort"); yy = y[o]
    tp = np.cumsum(yy); prec = tp / np.arange(1, len(yy) + 1)
    return float((prec * yy).sum() / max(yy.sum(), 1))


def f1s(y, pred):
    out = {}
    for c in (0, 1):
        tp = ((pred == c) & (y == c)).sum(); fp = ((pred == c) & (y != c)).sum(); fn = ((pred != c) & (y == c)).sum()
        p = tp / max(tp + fp, 1); r = tp / max(tp + fn, 1)
        out[c] = (2 * p * r / max(p + r, 1e-12), p, r)
    w = (y == 0).mean() * out[0][0] + (y == 1).mean() * out[1][0]
    fpr = ((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1)
    return {"f1_ponderado": float(w), "f1_ataque": float(out[1][0]), "precisao_ataque": float(out[1][1]),
            "recall_ataque": float(out[1][2]), "fpr": float(fpr)}


def best_thr(y, s):
    o = np.argsort(-s); yy = y[o]; tp = np.cumsum(yy); fp = np.cumsum(1 - yy)
    f1 = 2 * tp / (tp + fp + yy.sum()); k = int(np.argmax(f1))
    return float(s[o][k])


def treina_avalia(nome, Xtr, ytr, Xte, yte):
    t0 = time.time()
    dtr = xgb.DMatrix(Xtr, label=ytr); dte = xgb.DMatrix(Xte, label=yte)
    bst = xgb.train(PARAMS, dtr, N_TREES)
    s_tr = bst.predict(dtr); s_te = bst.predict(dte)
    thr = best_thr(ytr, s_tr)
    r = {"exp": nome, "n_treino": int(len(ytr)), "n_teste": int(len(yte)),
         "ataque_teste": float(yte.mean()), "roc_auc": float(roc_auc(yte, s_te)),
         "pr_auc": avg_precision(yte, s_te), "limiar_kim_0.36": f1s(yte, (s_te >= 0.36).astype(int)),
         "limiar_treino": dict(limiar=thr, **f1s(yte, (s_te >= thr).astype(int))), "segundos": time.time() - t0}
    print(json.dumps(r, indent=1), flush=True)
    return r


def dados_temporais(out, models_override=None, pcap=None):
    """Monta treino/teste temporais por arquivo com os rótulos do Kim."""
    Xtr, ytr, Xte, yte = [], [], [], []
    for f in FILES:
        if models_override is None:
            X = np.load(os.path.join(out, f + ".npz"))["X"]
        else:
            X = kf.extract(os.path.join(pcap, f), models_override)[0]
        y = np.zeros(len(X), np.int64)
        if f != FILES[0]:
            y[np.load(os.path.join(out, f + ".kim_attack_idx.npy"))] = 1
        k = int(FRAC * len(X))
        Xtr.append(X[:k]); ytr.append(y[:k]); Xte.append(X[k:]); yte.append(y[k:])
    return (np.concatenate(Xtr).astype(np.float32), np.concatenate(ytr),
            np.concatenate(Xte).astype(np.float32), np.concatenate(yte))


def modelos_treino_benigno(pcap):
    """Modelo de bytes ajustado só nos primeiros 70% (menos o 1º pacote) do benigno."""
    from collections import Counter
    vs = [v for _, raw in kf.read_pcap(os.path.join(pcap, FILES[0])) if (v := kf.views(raw)) is not None]
    vs = vs[1:]
    k = int(FRAC * len(vs))
    models = []
    for j in (2, 3, 4):
        m = kf.PaddedByteModel()
        for b, n in Counter(v[j] for v in vs[:k]).items():
            m.update(b, n)
        models.append(m.finalize())
    return models


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--exp", nargs="+", default=["exp1", "exp2a", "exp2b"])
    a = ap.parse_args()
    res = []
    if "exp1" in a.exp:
        R = np.load(os.path.join(a.out, "kim_rebuilt.npz"))
        res.append(treina_avalia("exp1: split do Kim (par/ímpar), vetores reconstruídos",
                                 R["Xtr"], R["ytr"], R["Xte"], R["yte"]))
    if "exp2a" in a.exp:
        res.append(treina_avalia("exp2a: split temporal 70/30 por arquivo, modelo de bytes do Kim",
                                 *dados_temporais(a.out)))
    if "exp2b" in a.exp:
        m = modelos_treino_benigno(a.pcap)
        res.append(treina_avalia("exp2b: split temporal 70/30, modelo de bytes só no treino",
                                 *dados_temporais(a.out, m, a.pcap)))
    with open(os.path.join(a.out, "kim_experiments.json"), "w") as fh:
        json.dump(res, fh, indent=1)


if __name__ == "__main__":
    main()
