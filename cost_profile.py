#!/usr/bin/env python3
"""Decomposição do CUSTO de extração por CATEGORIA de feature (método incremental).

Mede, de forma estável (várias repetições), quanto tempo cada categoria de feature acrescenta
à extração, cronometrando o laço inteiro sobre uma amostra computando subconjuntos CUMULATIVOS
de categorias. O custo de uma categoria é o delta de tempo entre dois níveis consecutivos
(cronometra-se o laço, sem overhead de timer por statement).

Categorias (= as do artigo, Tabela de features):
  parse (layer) · Time interval · Payload likelihood · Payload entropy · Payload changes
  · Length changes · Payload repetition · Absolute size · Source diversity

Também agrega a IMPORTÂNCIA (gain) por categoria (de results/model_16.json, se existir) e traça
os gráficos custo×categoria e custo×importância.

Uso:
    python cost_profile.py --n 200000 --reps 7 --out results
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict, deque

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
import someip                                          # noqa: E402
from bytemodel import hamming                          # noqa: E402
from extract import fit_bytemodels, BENIGN_FILE, L, _ts, PCAP_DIR_DEFAULT  # noqa: E402

# Categorias na ordem incremental: (nome, nº de features). parse é o nível base (0).
CATEGORIES = [
    ("Time interval", 1), ("Payload likelihood", 3), ("Payload entropy", 3),
    ("Payload changes", 3), ("Length changes", 2), ("Payload repetition", 1),
    ("Absolute size", 2), ("Source diversity", 1),
]
# feature -> categoria (para agregar a importância por categoria)
FEAT2CAT = (["Time interval"] + ["Payload likelihood"] * 3 + ["Payload entropy"] * 3
            + ["Payload changes"] * 3 + ["Length changes"] * 2
            + ["Payload repetition"] + ["Absolute size"] * 2 + ["Source diversity"])


def time_level(level: int, frames, models) -> float:
    """Processa `frames` computando as features até a categoria `level` e devolve o tempo (s).

    level 0 = só parse; 1 = +Time interval; 2 = +Payload likelihood; ... 8 = +Source diversity.
    """
    last = {}
    recent_pld = defaultdict(lambda: deque(maxlen=5))     # repeat_rate
    src_pld = defaultdict(lambda: deque(maxlen=1000))     # src_payload_div
    t0 = time.perf_counter()
    for raw, ts in frames:
        p = someip.parse(raw, ts)                          # nível 0: parse (layer)
        if p is None:
            continue
        if level >= 1:
            fk = someip.flow_key(p)
            st = last.get(fk)
            _iat = (p.ts - st["ts"]) if st else 0.0        # 1: Time interval
        if level >= 2:                                     # 2: Payload likelihood (x3)
            _ = models["someip"].loglik(p.pl_someip) if p.pl_someip else 0.0
            _ = models["sd"].loglik(p.pl_sd) if p.pl_sd else 0.0
            _ = models["l4"].loglik(p.pl_l4) if p.pl_l4 else 0.0
        if level >= 3:                                     # 3: Payload entropy (x3)
            _ = models["someip"].cross_entropy(p.pl_someip) if p.pl_someip else 0.0
            _ = models["sd"].cross_entropy(p.pl_sd) if p.pl_sd else 0.0
            _ = models["l4"].cross_entropy(p.pl_l4) if p.pl_l4 else 0.0
        if level >= 4:                                     # 4: Payload changes (x3, Hamming)
            if st:
                _ = hamming(p.pl_l4, st["l4"])
                _ = hamming(p.pl_someip, st["someip"]) if (p.pl_someip or st["someip"]) else 0
                _ = hamming(p.pl_sd, st["sd"]) if (p.pl_sd or st["sd"]) else 0
        if level >= 5:                                     # 5: Length changes (x2)
            if st:
                _ = p.ip_len - st["ip_len"]
                _ = len(p.pl_l4) - len(st["l4"])
        if level >= 6:                                     # 6: Payload repetition
            h = recent_pld[fk]
            _ = (sum(1 for q in h if q == p.pl_someip) / len(h)) if (h and p.pl_someip) else 0.0
            h.append(p.pl_someip)
        if level >= 7:                                     # 7: Absolute size (x2)
            _ = float(len(p.pl_someip)); _ = float(len(p.pl_l4))
        if level >= 8:                                     # 8: Source diversity
            wp = src_pld[p.src]
            if p.pl_someip:
                wp.append(p.pl_someip)
            _ = (len(set(wp)) / len(wp)) if len(wp) > 1 else 0.0
        if level >= 1:
            last[fk] = {"ts": p.ts, "ip_len": p.ip_len, "l4": p.pl_l4,
                        "someip": p.pl_someip, "sd": p.pl_sd}
    return time.perf_counter() - t0


def load_frames(pcap_dir: str, n: int):
    from scapy.utils import RawPcapReader
    frames = []
    for raw, meta in RawPcapReader(os.path.join(pcap_dir, BENIGN_FILE)):
        frames.append((raw, _ts(meta)))
        if len(frames) >= n:
            break
    return frames


def importance_by_category(model_path: str) -> dict | None:
    if not os.path.exists(model_path):
        return None
    from xgboost import XGBClassifier
    clf = XGBClassifier(); clf.load_model(model_path)
    sc = clf.get_booster().get_score(importance_type="gain")
    imp = np.array([sc.get(f"f{i}", 0.0) for i in range(16)])
    agg = defaultdict(float)
    for i, c in enumerate(FEAT2CAT):
        agg[c] += float(imp[i])
    return dict(agg)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir", default=PCAP_DIR_DEFAULT)
    ap.add_argument("--n", type=int, default=200000, help="pacotes na amostra")
    ap.add_argument("--reps", type=int, default=7, help="repetições por nível (estabilidade)")
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    print(f"[1/4] byte-models no benigno (amostra {a.n:,})...")
    models, _ = fit_bytemodels(a.pcap_dir, max_packets=a.n)
    print(f"[2/4] carregando {a.n:,} frames...")
    frames = load_frames(a.pcap_dir, a.n)
    npk = len(frames)

    print(f"[3/4] medindo {a.reps}x cada nível (0..8)...")
    # matriz tempos[nível][rep] (s); warm-up 1 rep descartada por nível
    times = np.zeros((9, a.reps))
    for lvl in range(9):
        time_level(lvl, frames[: min(2000, npk)], models)        # warm-up
        for r in range(a.reps):
            times[lvl, r] = time_level(lvl, frames, models)
        print(f"   nível {lvl}: {times[lvl].mean()*1e3:8.1f} ms  (±{times[lvl].std()*1e3:.1f})")

    # custo por categoria = delta entre níveis, por pacote (us)
    per_pkt = times / npk * 1e6                                    # us/pacote por nível
    base_parse = float(per_pkt[0].mean())
    cats, cost_mean, cost_std = [], [], []
    for k, (name, _nf) in enumerate(CATEGORIES, start=1):
        d = per_pkt[k] - per_pkt[k - 1]                           # amostras do delta
        cats.append(name); cost_mean.append(float(d.mean())); cost_std.append(float(d.std()))
    total = base_parse + sum(cost_mean)

    imp = importance_by_category(os.path.join(a.out, "model_16.json"))

    out = {"n_packets": npk, "reps": a.reps,
           "parse_us_per_pkt": base_parse,
           "cost_by_category_us_per_pkt": {c: {"mean": m, "std": s}
                                           for c, m, s in zip(cats, cost_mean, cost_std)},
           "total_extraction_us_per_pkt": total,
           "importance_gain_by_category": imp}
    json.dump(out, open(os.path.join(a.out, "cost_by_category.json"), "w"), indent=2)

    print("\n[4/4] custo por categoria (us/pacote):")
    print(f"   {'parse (layer)':22} {base_parse:7.3f}")
    for c, m, s in zip(cats, cost_mean, cost_std):
        print(f"   {c:22} {m:7.3f}  (±{s:.3f})")
    print(f"   {'TOTAL extração':22} {total:7.3f}")

    # ---- gráficos ----
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    labels = ["parse"] + cats
    vals = [base_parse] + cost_mean
    errs = [0.0] + cost_std
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.bar(range(len(labels)), vals, yerr=errs, capsize=3)
    ax.set_xticks(range(len(labels))); ax.set_xticklabels(labels, rotation=35, ha="right")
    ax.set_ylabel("Custo de extração (us/pacote)")
    ax.set_title(f"Custo por categoria de feature (amostra {npk:,}, {a.reps} reps)")
    plt.tight_layout(); fig.savefig(os.path.join(a.out, "cost_by_category.png"), dpi=200, bbox_inches="tight")

    if imp:
        fig, ax1 = plt.subplots(figsize=(9, 4.5))
        x = np.arange(len(cats)); w = 0.4
        ax1.bar(x - w / 2, cost_mean, w, label="custo (us/pkt)", color="tab:blue")
        ax1.set_ylabel("Custo (us/pacote)", color="tab:blue"); ax1.tick_params(axis="y", labelcolor="tab:blue")
        ax2 = ax1.twinx()
        ax2.bar(x + w / 2, [imp.get(c, 0.0) for c in cats], w, label="importância (gain)", color="tab:orange")
        ax2.set_ylabel("Importância (gain)", color="tab:orange"); ax2.tick_params(axis="y", labelcolor="tab:orange")
        ax1.set_xticks(x); ax1.set_xticklabels(cats, rotation=35, ha="right")
        ax1.set_title("Custo × Importância por categoria")
        plt.tight_layout(); fig.savefig(os.path.join(a.out, "cost_vs_importance.png"), dpi=200, bbox_inches="tight")

    print("\nsalvo:", os.path.abspath(a.out),
          "(cost_by_category.json, cost_by_category.png" + (", cost_vs_importance.png)" if imp else ")"))


if __name__ == "__main__":
    main()
