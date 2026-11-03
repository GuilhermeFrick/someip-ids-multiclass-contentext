"""Multiclasse (5 classes) com as 12 features fiéis ao Kim, para ver a matriz de confusão.

Classes: 0 normal, 1 DoS, 2 Fuzzy (os 3 arquivos), 3 MITM single, 4 MITM multi. O rótulo de
ataque é o do Kim (kim_attack_idx.npy); a família vem do arquivo. XGBoost com os hiperparâmetros
da Tabela 2 do artigo, multi:softprob.

  mc_kim      : divisão do Kim (par/ímpar global, mesma montagem de scripts/kim_rebuild.py)
  mc_temporal : primeiros 70% de cada PCAP no treino, últimos 30% no teste

Uso (someip-parity:1): python3 scripts/kim_multiclass.py --out /work/kimf --exp mc_kim mc_temporal
"""
import argparse
import json
import os
import sys
import time

import numpy as np
import xgboost as xgb

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kim_validate import FILES  # noqa: E402
from kim_label_rule import ORDEM, ORDEM_NORMAL  # noqa: E402

CLASSES = ["normal", "dos", "fuzzy", "mitm_single", "mitm_multi"]
FAMILIA = {"dos_noti_flood.pcap": 1, "fuzzy_sd_offer_rand_noti(1).pcap": 2,
           "fuzzy_sd_offer_rand_noti(2).pcap": 2, "fuzzy_sd_offer_rand_noti(3).pcap": 2,
           "mitm_single_attacker.pcap": 3, "mitm_multi_attacker.pcap": 4}
PARAMS = dict(objective="multi:softprob", num_class=5, eta=0.05, max_depth=6, subsample=0.8,
              colsample_bytree=0.8, reg_lambda=1.0, gamma=0.0, min_child_weight=1,
              tree_method="hist", seed=42, nthread=os.cpu_count())
N_TREES = 1000


def por_arquivo(out):
    """{arquivo: (X bruto, rótulo multiclasse)}"""
    d = {}
    for f in FILES:
        X = np.load(os.path.join(out, f + ".npz"))["X"].astype(np.float32)
        y = np.zeros(len(X), np.int64)
        if f in FAMILIA:
            y[np.load(os.path.join(out, f + ".kim_attack_idx.npy"))] = FAMILIA[f]
        d[f] = (X, y)
    return d


def split_kim(d):
    partes = [d[FILES[0]]]
    partes += [(d[f][0][d[f][1] > 0], d[f][1][d[f][1] > 0]) for f in ORDEM]
    partes += [(d[f][0][d[f][1] == 0], d[f][1][d[f][1] == 0]) for f in ORDEM_NORMAL]
    X = np.concatenate([p[0] for p in partes]); y = np.concatenate([p[1] for p in partes])
    return X[0::2], y[0::2], X[1::2], y[1::2]


def split_temporal(d, frac=0.7):
    tr, te = [], []
    for f in FILES:
        X, y = d[f]; k = int(frac * len(X))
        tr.append((X[:k], y[:k])); te.append((X[k:], y[k:]))
    c = lambda ps: (np.concatenate([p[0] for p in ps]), np.concatenate([p[1] for p in ps]))
    return (*c(tr), *c(te))


def avalia(nome, Xtr, ytr, Xte, yte, salvar=None):
    t0 = time.time()
    bst = xgb.train(PARAMS, xgb.DMatrix(Xtr, label=ytr), N_TREES)
    if salvar:
        bst.save_model(salvar)
    pred = bst.predict(xgb.DMatrix(Xte)).argmax(1)
    cm = np.zeros((5, 5), np.int64)
    np.add.at(cm, (yte, pred), 1)
    por = {}
    for c in range(5):
        tp = cm[c, c]; p = tp / max(cm[:, c].sum(), 1); r = tp / max(cm[c].sum(), 1)
        por[CLASSES[c]] = {"suporte": int(cm[c].sum()), "precisao": float(p), "recall": float(r),
                           "f1": float(2 * p * r / max(p + r, 1e-12))}
    res = {"exp": nome, "macro_f1": float(np.mean([v["f1"] for v in por.values()])),
           "fpr_normal": float(1 - por["normal"]["recall"]), "por_classe": por,
           "matriz_confusao": cm.tolist(), "importancia_gain": bst.get_score(importance_type="gain"),
           "segundos": time.time() - t0}
    print("\n== %s  macro-F1 %.4f  FP %.3f%%" % (nome, res["macro_f1"], 100 * res["fpr_normal"]))
    print("%-12s %s" % ("real\\pred", " ".join("%11s" % c for c in CLASSES)))
    for c in range(5):
        print("%-12s %s" % (CLASSES[c], " ".join("%11d" % v for v in cm[c])))
    for c, v in por.items():
        print("   %-12s suporte %8d  precisão %.3f  recall %.3f  F1 %.3f" % (c, v["suporte"], v["precisao"], v["recall"], v["f1"]))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--exp", nargs="+", default=["mc_kim", "mc_temporal"])
    a = ap.parse_args()
    d = por_arquivo(a.out)
    res = []
    if "mc_kim" in a.exp:
        res.append(avalia("multiclasse, 12 features do Kim, divisão do Kim (par/ímpar)", *split_kim(d)))
    if "mc_temporal" in a.exp:
        res.append(avalia("multiclasse, 12 features do Kim, divisão temporal 70/30", *split_temporal(d)))
    with open(os.path.join(a.out, "kim_multiclass.json"), "w") as fh:
        json.dump(res, fh, indent=1)


if __name__ == "__main__":
    main()
