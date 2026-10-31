#!/usr/bin/env python3
"""Leave-one-out das 4 features propostas, sobre o conjunto completo de 16.

Responde o que a ablacao por subconjunto nao respondia: com TODAS as outras
presentes, qual o efeito de remover cada feature proposta isoladamente?
"""
import json, os, sys, time
import numpy as np
sys.path.insert(0, "src")
import pipeline
from sklearn.metrics import classification_report
from xgboost import XGBClassifier

PROPOSTAS = {"payload repetition": [12], "absolute size": [13, 14],
             "source diversity": [15]}
z = np.load("results/features.npz", allow_pickle=True)
Xn, y, counts = z["Xn"], z["y"], z["counts"].tolist()
itr, ite = pipeline.temporal_split(counts)
cls = pipeline.CLASSES
ALL = list(range(16))

def run(idx, nome):
    t0 = time.time()
    clf = XGBClassifier(**pipeline.model_params())
    clf.fit(Xn[np.ix_(itr, idx)], y[itr])
    rep = classification_report(y[ite], clf.predict(Xn[np.ix_(ite, idx)]),
                                target_names=cls, digits=4, output_dict=True,
                                zero_division=0)
    r = {"remocao": nome, "n_feat": len(idx),
         "macro_f1": float(rep["macro avg"]["f1-score"]),
         "f1": {c: float(rep[c]["f1-score"]) for c in cls}}
    print("  %-22s nf=%2d  macro=%.4f  fuzzy=%.4f  mitm_multi=%.4f  (%ds)" %
          (nome, len(idx), r["macro_f1"], r["f1"]["fuzzy"], r["f1"]["mitm_multi"],
           time.time()-t0), flush=True)
    return r

print("=== leave-one-out das 4 features propostas (modelo final) ===")
out = [run(ALL, "nenhuma (all16)")]
for nome, drop in PROPOSTAS.items():
    out.append(run([i for i in ALL if i not in drop], "sem " + nome))
json.dump(out, open("results/leave_one_out.json", "w"), indent=2)
print("\n[ok] results/leave_one_out.json")
