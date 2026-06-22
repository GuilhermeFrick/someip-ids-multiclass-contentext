"""Efeito de usar os HIPERPARÂMETROS DO KIM no nosso multiclasse content_ext.

Kim (Tabela 2): 1000 árvores, lr 0.05, depth 6, subsample 0.8, colsample 0.8, L2=1.0.
Nosso atual: 300 árvores, lr 0.3, depth 8, sem subsampling.

Roda os DOIS splits (aleatório e temporal por arquivo) com os params do Kim e compara
com os nossos números já conhecidos (random 0.9936 / temporal 0.9658).

Uso: python kim_params_experiment.py
"""
from __future__ import annotations

import json
import sys
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, classification_report
from xgboost import XGBClassifier

CLASSES = ["normal", "dos", "fuzzy", "mitm_single", "mitm_multi"]
N = len(CLASSES); SEED = 0
CONTENT_EXT = list(range(12)) + [12, 13, 14, 16]
FILE_COUNTS = [("benign",2193802),("dos",1864530),("fuzzy1",2197113),("fuzzy2",1304154),
               ("fuzzy3",2223650),("mitm_multi",2412529),("mitm_single",2037576)]

KIM = dict(objective="multi:softprob", num_class=N, n_estimators=1000, max_depth=6,
           learning_rate=0.05, subsample=0.8, colsample_bytree=0.8, reg_lambda=1.0,
           tree_method="hist", n_jobs=-1, eval_metric="mlogloss")
OURS_REF = {"random": 0.9936, "temporal": 0.9658}   # nossos params (já medidos)


def rep(tag, y_te, y_pred):
    r = classification_report(y_te, y_pred, target_names=CLASSES, digits=4, output_dict=True)
    print(f"\n== {tag} (params do Kim) ==", flush=True)
    for c in CLASSES:
        print(f"  {c:12} F1={r[c]['f1-score']:.4f}", flush=True)
    mf = r["macro avg"]["f1-score"]
    print(f"  macro-F1={mf:.4f}  accuracy={r['accuracy']:.4f}", flush=True)
    return mf


def temporal_idx(n):
    tr, te, s = [], [], 0
    for _, c in FILE_COUNTS:
        cut = s + int(c * 0.7); tr.append(np.arange(s, cut)); te.append(np.arange(cut, s + c)); s += c
    return np.concatenate(tr), np.concatenate(te)


def main():
    X = np.load("data/ours_ext/X.npz")["a"][:, CONTENT_EXT]
    y = np.load("data/ours_ext/y_multi.npz")["a"]
    print(f"X={X.shape}", flush=True)
    out = {}

    print("\n[1/2] split ALEATÓRIO (params Kim)...", flush=True)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.30, random_state=SEED, stratify=y)
    m = XGBClassifier(**KIM); m.fit(Xtr, ytr)
    out["random"] = rep("ALEATÓRIO", yte, m.predict(Xte))

    print("\n[2/2] split TEMPORAL por arquivo (params Kim)...", flush=True)
    itr, ite = temporal_idx(len(y))
    m2 = XGBClassifier(**KIM); m2.fit(X[itr], y[itr])
    out["temporal"] = rep("TEMPORAL", y[ite], m2.predict(X[ite]))

    print("\n===== COMPARAÇÃO (macro-F1) =====", flush=True)
    print(f"  {'split':10}{'params Kim':>12}{'nossos params':>16}", flush=True)
    for k in ("random", "temporal"):
        print(f"  {k:10}{out[k]:11.4f}{OURS_REF[k]:15.4f}", flush=True)
    json.dump({"kim_params": out, "our_params_ref": OURS_REF},
              open("kim_params_experiment.json", "w"), indent=2)
    print("\n-> kim_params_experiment.json", flush=True)


if __name__ == "__main__":
    main()
