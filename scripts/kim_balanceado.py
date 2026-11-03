"""Teste balanceado do Kim (Tabela 3 do artigo): o mesmo modelo, avaliado também num teste
com o normal subamostrado até o número de ataques (831.159 de cada), como o artigo faz.

Divisão do Kim (par/ímpar), vetores reconstruídos (kim_rebuilt.npz), XGBoost binário da
Tabela 2, sem CTGAN. Artigo: ROC-AUC 0,99 (desbalanceado) e 0,97 (balanceado); P = R = F1 = 0,97.

Uso (someip-parity:1): python3 scripts/kim_balanceado.py --out /work/kimf
"""
import argparse
import json
import os
import sys

import numpy as np
import xgboost as xgb

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kim_experiments import PARAMS, N_TREES, roc_auc, avg_precision, f1s  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    R = np.load(os.path.join(a.out, "kim_rebuilt.npz"))
    bst = xgb.train(PARAMS, xgb.DMatrix(R["Xtr"], label=R["ytr"]), N_TREES)
    s = bst.predict(xgb.DMatrix(R["Xte"])); y = R["yte"]
    rng = np.random.default_rng(0)
    ia = np.flatnonzero(y == 1)
    bal = np.concatenate([ia, rng.choice(np.flatnonzero(y == 0), len(ia), replace=False)])
    res = {}
    for nome, idx in (("desbalanceado", np.arange(len(y))), ("balanceado", bal)):
        yy, ss = y[idx], s[idx]
        pred = (ss >= 0.36).astype(int)
        m = f1s(yy, pred)
        # precisão/recall ponderados por classe, como o artigo parece reportar
        pw = rw = 0.0
        for c in (0, 1):
            w = (yy == c).mean(); tp = ((pred == c) & (yy == c)).sum()
            pw += w * tp / max((pred == c).sum(), 1); rw += w * tp / max((yy == c).sum(), 1)
        res[nome] = dict(n=int(len(yy)), roc_auc=float(roc_auc(yy, ss)), pr_auc=avg_precision(yy, ss),
                         precisao_ponderada=float(pw), recall_ponderado=float(rw), **m)
        print(nome, json.dumps(res[nome], indent=1), flush=True)
    json.dump(res, open(os.path.join(a.out, "kim_balanceado.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
