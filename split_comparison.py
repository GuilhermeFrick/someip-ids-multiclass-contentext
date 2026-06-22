"""Compara SPLIT ALEATÓRIO vs SPLIT TEMPORAL POR ARQUIVO no IDS multiclasse content_ext.

Responde à crítica de vazamento temporal: o split aleatório embaralha pacotes da mesma rajada
de ataque entre treino/teste (otimista). O split temporal por arquivo treina nos primeiros 70%
(cronológicos) de cada PCAP e testa nos 30% finais — sem vazamento de continuidade.

As features (data/ours_ext/X.npz) estão na ORDEM DE EXTRAÇÃO: arquivos concatenados nesta ordem,
cada um em ordem de pacote (temporal). Fronteiras reconstruídas pelas contagens da extração.

Uso: python split_comparison.py
"""
from __future__ import annotations

import json
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, classification_report
from xgboost import XGBClassifier

CLASSES = ["normal", "dos", "fuzzy", "mitm_single", "mitm_multi"]
N = len(CLASSES)
SEED = 0
CONTENT_EXT = list(range(12)) + [12, 13, 14, 16]

# contagens por arquivo (saída da extração), na ordem de concatenação
FILE_COUNTS = [
    ("benign", 2193802), ("dos", 1864530), ("fuzzy1", 2197113), ("fuzzy2", 1304154),
    ("fuzzy3", 2223650), ("mitm_multi", 2412529), ("mitm_single", 2037576),
]


def xgb():
    return XGBClassifier(objective="multi:softprob", num_class=N, n_estimators=300, max_depth=8,
                         learning_rate=0.3, tree_method="hist", max_bin=256, n_jobs=-1,
                         eval_metric="mlogloss")


def report(tag, y_te, y_pred):
    rep = classification_report(y_te, y_pred, target_names=CLASSES, digits=4, output_dict=True)
    print(f"\n== {tag} ==")
    for c in CLASSES:
        print(f"  {c:12} F1={rep[c]['f1-score']:.4f}")
    print(f"  macro-F1={rep['macro avg']['f1-score']:.4f}  accuracy={rep['accuracy']:.4f}")
    return {c: rep[c]["f1-score"] for c in CLASSES} | {"macro_f1": rep["macro avg"]["f1-score"],
                                                       "accuracy": rep["accuracy"]}


def temporal_indices(n_total, frac=0.7):
    """Por arquivo: primeiros 70% -> treino, últimos 30% -> teste."""
    tr, te, start = [], [], 0
    for _, cnt in FILE_COUNTS:
        cut = start + int(cnt * frac)
        tr.append(np.arange(start, cut))
        te.append(np.arange(cut, start + cnt))
        start += cnt
    assert start == n_total, f"contagens ({start}) != total ({n_total})"
    return np.concatenate(tr), np.concatenate(te)


def main():
    X = np.load("data/ours_ext/X.npz")["a"][:, CONTENT_EXT]
    y = np.load("data/ours_ext/y_multi.npz")["a"]
    print(f"X={X.shape}")
    out = {}

    # 1) split aleatório (o original — otimista)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.30, random_state=SEED, stratify=y)
    m = xgb(); m.fit(Xtr, ytr)
    out["aleatorio"] = report("SPLIT ALEATÓRIO (70/30)", yte, m.predict(Xte))

    # 2) split temporal por arquivo (sem vazamento)
    itr, ite = temporal_indices(len(y))
    dist_te = {CLASSES[c]: int((y[ite] == c).sum()) for c in range(N)}
    print(f"\nteste temporal — distribuição: {dist_te}")
    m2 = xgb(); m2.fit(X[itr], y[itr])
    out["temporal"] = report("SPLIT TEMPORAL POR ARQUIVO (70/30)", y[ite], m2.predict(X[ite]))

    print("\n===== COMPARAÇÃO (macro-F1) =====")
    print(f"  aleatório : {out['aleatorio']['macro_f1']:.4f}")
    print(f"  temporal  : {out['temporal']['macro_f1']:.4f}")
    print(f"  (zero-day leave-one-attack-out, ref. someip-ids-benchmark: ~0.60)")
    json.dump(out, open("split_comparison.json", "w"), indent=2)
    print("\n-> split_comparison.json")


if __name__ == "__main__":
    main()
