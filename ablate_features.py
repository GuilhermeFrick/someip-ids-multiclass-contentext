#!/usr/bin/env python3
"""Ablação de features: qual feature sustenta qual classe.

Este script produz o resultado citado no artigo ao atribuir a separação do
Fuzzy à feature de diversidade por origem. Está aqui porque é ele que torna
aquela afirmação verificável.

===============================================================================
POR QUE ABLAÇÃO E NÃO IMPORTÂNCIA (GAIN)
===============================================================================

O `gain` do XGBoost é agregado sobre as cinco classes. Uma feature decisiva
para duas classes minoritárias aparece com ganho baixo, e some no ranking.

Foi exatamente o que aconteceu: a `source diversity` tem o MENOR ganho entre as
features de conteúdo e, removida, derruba o Fuzzy de 0,999 para 0,544 e o
MITM-multi de 0,858 para 0,575. A atribuição original, feita por ganho, apontava
a feature errada.

A ablação responde a pergunta certa: *o que acontece com cada classe se esta
feature não existir?*

===============================================================================
O QUE SE MEDE
===============================================================================

Para cada subconjunto de features: macro-F1 e F1 POR CLASSE (o agregado
esconde justamente o efeito que interessa), mais o custo de extração estimado
a partir da decomposição medida por categoria.

Observação sobre o custo: uma categoria só é cobrada se ao menos uma de suas
features estiver presente. Remover uma feature de uma categoria de três não
economiza nada, porque o cálculo da categoria continua sendo feito.

Uso:
    python ablate_features.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
import pipeline  # noqa: E402

# Índice da feature -> categoria, e custo MEDIDO por categoria (us/pacote),
# da decomposição incremental reportada no artigo.
CAT_OF = {0: "time_interval",
          1: "likelihood", 2: "likelihood", 3: "likelihood",
          4: "entropy", 5: "entropy", 6: "entropy",
          7: "changes", 8: "changes", 9: "changes",
          10: "length", 11: "length",
          12: "repetition",
          13: "abs_size", 14: "abs_size",
          15: "src_diversity"}
CAT_US = {"parse": 2.350, "time_interval": 0.511, "likelihood": 3.553,
          "entropy": 3.320, "changes": 2.290, "length": 0.085,
          "repetition": 0.550, "abs_size": 0.114, "src_diversity": 9.132}

ALL16 = list(range(16))
BASE12 = list(range(12))      # as 12 do baseline, sem as 4 propostas

SUBSETS = {
    "base12":     BASE12,                               # baseline
    "all16":      ALL16,                                # conjunto proposto
    "no_srcdiv":  [i for i in ALL16 if i != 15],        # sem a mais cara
    "no_lowgain": [i for i in ALL16 if i not in (0, 10, 11)],   # sem as de menor ganho
    "base12_rep": BASE12 + [12],                        # baseline + repeticao
    "lean":       [i for i in ALL16 if i not in (0, 10, 11, 15)],
}


def extraction_us(idx) -> float:
    """Custo de extração do subconjunto: parse mais as categorias presentes."""
    cats = {CAT_OF[i] for i in idx}
    return round(CAT_US["parse"] + sum(CAT_US[c] for c in cats), 3)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", default="results/features.npz")
    ap.add_argument("--out", default="results/ablacao_features.json")
    ap.add_argument("--rounds", type=int, default=pipeline.MODEL_ROUNDS)
    ap.add_argument("--depth", type=int, default=pipeline.MODEL_DEPTH)
    a = ap.parse_args()

    from sklearn.metrics import classification_report
    from xgboost import XGBClassifier

    z = np.load(a.cache, allow_pickle=True)
    Xn, y, counts = z["Xn"], z["y"], z["counts"].tolist()
    itr, ite = pipeline.temporal_split(counts)
    cls = pipeline.CLASSES
    print(f"[modelo] {a.rounds} estimadores, profundidade {a.depth}")
    print(f"[split]  treino={len(itr):,}  teste={len(ite):,}")

    rows = []
    for name, idx in SUBSETS.items():
        t0 = time.time()
        clf = XGBClassifier(objective="multi:softprob", num_class=pipeline.N,
                            n_estimators=a.rounds, max_depth=a.depth,
                            learning_rate=0.3, tree_method="hist", device="cpu",
                            max_bin=256, n_jobs=-1, eval_metric="mlogloss")
        clf.fit(Xn[np.ix_(itr, idx)], y[itr])
        rep = classification_report(y[ite], clf.predict(Xn[np.ix_(ite, idx)]),
                                    target_names=cls, digits=4,
                                    output_dict=True, zero_division=0)
        rows.append({"subset": name, "n_feat": len(idx),
                     "macro_f1": float(rep["macro avg"]["f1-score"]),
                     "extracao_us": extraction_us(idx),
                     "f1": {c: float(rep[c]["f1-score"]) for c in cls}})
        r = rows[-1]
        print(f"  {name:12s} nf={r['n_feat']:2d}  macro-F1={r['macro_f1']:.4f}  "
              f"fuzzy={r['f1']['fuzzy']:.4f}  mitm_multi={r['f1']['mitm_multi']:.4f}  "
              f"extracao={r['extracao_us']:5.2f}us  ({time.time()-t0:.0f}s)", flush=True)

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump({"modelo": {"rounds": a.rounds, "depth": a.depth}, "ablacao": rows},
              open(a.out, "w"), indent=2)
    print(f"\n[ok] {a.out}")


if __name__ == "__main__":
    main()
