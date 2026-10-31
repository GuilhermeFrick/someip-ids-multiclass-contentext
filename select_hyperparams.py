#!/usr/bin/env python3
"""Seleção dos hiperparâmetros do detector, em VALIDAÇÃO.

Este script produz a escolha reportada no artigo (Tabela de hiperparâmetros).
Está aqui, e não num repositório de ferramentas, porque é ele que torna aquela
afirmação reproduzível.

===============================================================================
POR QUE NÃO SELECIONAR PELO TESTE
===============================================================================

Escolher, entre N candidatos, o de melhor número no conjunto de **teste** faz
parte do que se mede virar ruído daquele conjunto: a métrica publicada fica
otimista por construção, e não há como distinguir mérito de sorte.

No nosso caso isso não foi hipotético. Numa primeira varredura feita sobre o
teste, a configuração eleita (50 estimadores, profundidade 4) tinha:

    - o MELHOR macro-F1 de teste   (0,9695, 1º entre 15)
    - a SÉTIMA melhor validação    (0,9418)

Vantagem concentrada justamente no conjunto de reporte. A seleção honesta elege
outra configuração.

===============================================================================
O MÉTODO
===============================================================================

Split aninhado, preservando a ordem temporal dentro de cada arquivo de captura:

    |<--------------- treino (70%) --------------->|<---- teste (30%) ---->|
    |<-- treino interno (49%) -->|<-- val (21%) -->|
                                                     ^
                                      o teste nunca é tocado na escolha

A ordem temporal importa porque o tráfego tem deriva: o teste é um período
posterior ao de treino. Um split aleatório deixaria o modelo ver o futuro e
esconderia o sobreajuste. A validação reproduz essa mesma relação dentro do
treino, para que a escolha seja feita sob a condição em que o modelo será
julgado.

Três etapas:

    1. VARRER    treina cada configuração no treino interno, avalia na validação
    2. ESCOLHER  seleciona a de maior macro-F1 na validação
    3. REPORTAR  retreina a vencedora no treino COMPLETO e só então toca no teste

Uso:
    python select_hyperparams.py                      # usa results/features.npz
    python select_hyperparams.py --pcap-dir data/pcap # extrai se nao houver cache
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

# Grade da varredura. `rounds` são as rodadas de boosting; com 5 classes o
# XGBoost constrói rounds x 5 árvores no total.
ROUNDS = [25, 50, 100, 200, 300]
DEPTHS = [4, 6, 8]

# Configuração usada antes desta varredura, mantida para quantificar o ganho.
BASELINE = (300, 8)


def nested_split(counts, frac_test=0.70, frac_val=0.70):
    """Corta treino interno, validação, treino completo e teste, nessa ordem.

    O corte é feito DENTRO de cada arquivo e em sequência, nunca embaralhando:
    a validação é sempre um período posterior ao do treino interno, e o teste
    posterior a ambos. É isso que preserva a ordem temporal.
    """
    inner, val, full, test = [], [], [], []
    s = 0
    for c in counts:
        cut_te = s + int(c * frac_test)              # fim do treino completo
        cut_va = s + int(c * frac_test * frac_val)   # fim do treino interno
        inner.append(np.arange(s, cut_va))
        val.append(np.arange(cut_va, cut_te))
        full.append(np.arange(s, cut_te))
        test.append(np.arange(cut_te, s + c))
        s += c
    return (np.concatenate(inner), np.concatenate(val),
            np.concatenate(full), np.concatenate(test))


def load_features(cache: str, pcap_dir: str):
    """Extrai uma vez e cacheia: a extração NÃO depende dos hiperparâmetros."""
    if os.path.exists(cache):
        print(f"[cache] {cache}")
        z = np.load(cache, allow_pickle=True)
        return z["Xn"], z["y"], z["counts"].tolist()
    print("[extracao] dataset completo (alguns minutos)...", flush=True)
    t0 = time.time()
    Xn, y, counts, _t, _m, _mm = pipeline.extract_all(pcap_dir, max_packets=None)
    print(f"[extracao] {time.time()-t0:.0f}s, X={Xn.shape}")
    os.makedirs(os.path.dirname(cache) or ".", exist_ok=True)
    np.savez_compressed(cache, Xn=Xn, y=y, counts=np.array(counts, dtype=object))
    return Xn, y, counts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir", default="data/pcap")
    ap.add_argument("--cache", default="results/features.npz")
    ap.add_argument("--out", default="results/selecao_hiperparametros.json")
    a = ap.parse_args()

    from sklearn.metrics import classification_report
    from xgboost import XGBClassifier

    Xn, y, counts = load_features(a.cache, a.pcap_dir)
    idx, cls = pipeline.CONTENT_EXT, pipeline.CLASSES
    inner, val, full, test = nested_split(counts)
    print(f"[split] treino interno={len(inner):,}  validacao={len(val):,}  "
          f"treino completo={len(full):,}  teste={len(test):,}")

    def fit_eval(tr, ev, rounds, depth):
        """Treina em `tr`, avalia em `ev`. Demais hiperparâmetros fixos."""
        clf = XGBClassifier(objective="multi:softprob", num_class=pipeline.N,
                            n_estimators=rounds, max_depth=depth,
                            learning_rate=0.3, tree_method="hist", device="cpu",
                            max_bin=256, n_jobs=-1, eval_metric="mlogloss")
        clf.fit(Xn[np.ix_(tr, idx)], y[tr])
        return classification_report(y[ev], clf.predict(Xn[np.ix_(ev, idx)]),
                                     target_names=cls, digits=4,
                                     output_dict=True, zero_division=0)

    # ---------- 1. varrer, avaliando sempre na VALIDAÇÃO ----------
    print("\n=== 1. varredura na validacao ===")
    rows = []
    for depth in DEPTHS:
        for rounds in ROUNDS:
            t0 = time.time()
            rep = fit_eval(inner, val, rounds, depth)
            m = rep["macro avg"]["f1-score"]
            rows.append({"rounds": rounds, "depth": depth, "trees": rounds * pipeline.N,
                         "macro_f1_val": float(m),
                         "f1_val": {c: float(rep[c]["f1-score"]) for c in cls}})
            print(f"  r{rounds:<3d} d{depth}  macro-F1(val)={m:.4f}  "
                  f"({time.time()-t0:.0f}s)", flush=True)

    # ---------- 2. escolher pela VALIDAÇÃO, e só por ela ----------
    best = max(rows, key=lambda r: r["macro_f1_val"])
    print(f"\n[escolhido] {best['rounds']} estimadores, profundidade {best['depth']}"
          f"  ({best['trees']} arvores)  macro-F1(val)={best['macro_f1_val']:.4f}")

    # ---------- 3. retreinar no treino completo e reportar no TESTE ----------
    print("\n=== 3. teste (nao participou da escolha) ===")
    final = {}
    for tag, (r, d) in {"escolhido": (best["rounds"], best["depth"]),
                        "anterior": BASELINE}.items():
        rep = fit_eval(full, test, r, d)
        final[tag] = {"rounds": r, "depth": d, "trees": r * pipeline.N,
                      "macro_f1_test": float(rep["macro avg"]["f1-score"]),
                      "f1_test": {c: float(rep[c]["f1-score"]) for c in cls}}
        print(f"  {tag:10s} r{r} d{d}  macro-F1(teste)="
              f"{final[tag]['macro_f1_test']:.4f}")

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump({"grade": {"rounds": ROUNDS, "depths": DEPTHS},
               "validacao": rows, "teste": final},
              open(a.out, "w"), indent=2)
    print(f"\n[ok] {a.out}")


if __name__ == "__main__":
    main()
