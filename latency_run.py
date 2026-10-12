#!/usr/bin/env python3
"""Mede a latência por estágio/por pacote (src/latency.py) carregando os artefatos
salvos por run_experiment.py (modelo + byte-models + min-max + índices das features).

Pensado para ser chamado sob core pinning + cota de CPU (scripts/cpu_quota.sh).

Uso:
    python latency_run.py --artifacts results --pcap data/pcap/benign_traffic.pcap --n 1000
"""
import argparse
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
import latency            # noqa: E402
from bytemodel import ByteModel  # noqa: E402
from extract import L     # noqa: E402
from xgboost import XGBClassifier  # noqa: E402


def load_bytemodels(art_dir: str) -> dict:
    d = np.load(os.path.join(art_dir, "bytemodels.npz"))
    models = {}
    for k in ("someip", "sd", "l4"):
        m = ByteModel(L[k])
        m.logP = d[k]
        models[k] = m
    return models


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", default="results", help="dir com model_16.json/bytemodels.npz/minmax.npy")
    ap.add_argument("--pcap", default="data/pcap/benign_traffic.pcap")
    ap.add_argument("--n", type=int, default=1000, help="pacotes amostrados (estilo Kim: 100+)")
    ap.add_argument("--warmup", type=int, default=2000)
    a = ap.parse_args()

    models = load_bytemodels(a.artifacts)
    mm = np.load(os.path.join(a.artifacts, "minmax.npy"))   # (2, 21)
    content_idx = json.load(open(os.path.join(a.artifacts, "content_idx.json")))
    clf = XGBClassifier()
    clf.load_model(os.path.join(a.artifacts, "model_16.json"))

    res = latency.measure(a.pcap, models, clf, content_idx, (mm[0], mm[1]),
                          n_samples=a.n, warmup=a.warmup)
    print(json.dumps(res))


if __name__ == "__main__":
    main()
