"""Harness de latência por ESTÁGIO e por PACOTE (metodologia do Kim, 1 núcleo).

Mede, pacote a pacote (não em lote), os 4 estágios do detector online:
  1. layer          -- someip.parse  (Ethernet -> IP -> TCP/UDP -> SOME/IP -> SD)
  2. feature        -- FeatureStreamer.step  (vetor de features, com estado por fluxo/origem)
  3. classification -- clf.predict_proba de UM pacote (1 x d)
  4. decision       -- argmax da distribuicao de probabilidade

Reproduz a metodologia do Kim (Secao 6.4 / Tabela 5): amostra N pacotes apos um warm-up
e reporta a media. A latencia por pacote e o custo real online (diferente do throughput em
lote, que amortiza o overhead da chamada). Pensado para rodar em 1 nucleo com cota de CPU
(ver scripts/cpu_quota.sh), permitindo comparar C1 (16 feat, multiclasse) e Kim (12 feat,
binario) sob condicoes identicas.
"""
from __future__ import annotations

import time

import numpy as np
from scapy.utils import RawPcapReader

import someip
from extract import _ts
from extract_ext import FeatureStreamer   # (refatorado em extract_ext.py)


def _stats(samples_s) -> dict:
    """Converte uma lista de tempos (segundos) em estatisticas em microssegundos."""
    a = np.asarray(samples_s, dtype=np.float64) * 1e6
    return {"mean_us": float(a.mean()), "median_us": float(np.median(a)),
            "p95_us": float(np.percentile(a, 95)), "std_us": float(a.std())}


def measure(pcap_path, models, clf, content_idx, minmax,
            n_samples: int = 1000, warmup: int = 2000) -> dict:
    """Mede a latencia dos 4 estagios amostrando `n_samples` pacotes (apos `warmup`).

    Args:
      pcap_path: PCAP de onde amostrar (estado de fluxo/origem e construido na ordem real).
      models:    byte-models treinados no benigno (dict someip/sd/l4).
      clf:       classificador treinado (XGBoost; C1 multiclasse ou Kim binario).
      content_idx: indices das features do modelo (C1: CONTENT_EXT 16; Kim: range(12)).
      minmax:    (xmin, xmax) do treino, para normalizar igual ao pipeline.
      n_samples, warmup: amostragem estilo Kim (100+).
    """
    xmin, xmax = minmax
    rng = np.where(xmax > xmin, xmax - xmin, 1.0)
    streamer = FeatureStreamer()
    t_layer, t_feat, feats = [], [], []
    n = 0
    for raw, meta in RawPcapReader(pcap_path):
        t0 = time.perf_counter()
        p = someip.parse(raw, _ts(meta))
        t1 = time.perf_counter()
        if p is None:
            continue
        x = streamer.step(p, models)       # calcula features E atualiza o estado
        t2 = time.perf_counter()
        n += 1
        if n > warmup:
            t_layer.append(t1 - t0)
            t_feat.append(t2 - t1)
            feats.append(x)
        if len(feats) >= n_samples:
            break

    feats = np.asarray(feats, dtype=np.float64)
    Xn = ((feats - xmin) / rng).astype(np.float32)[:, content_idx]   # normaliza + seleciona

    _ = clf.predict_proba(Xn[:min(len(Xn), 256)])    # warm-up do modelo
    t_clf, t_dec = [], []
    for row in Xn:
        r = row.reshape(1, -1)
        a = time.perf_counter(); proba = clf.predict_proba(r); b = time.perf_counter()
        _ = proba.argmax(1); c = time.perf_counter()
        t_clf.append(b - a); t_dec.append(c - b)

    layer, feat = _stats(t_layer), _stats(t_feat)
    clf_s, dec = _stats(t_clf), _stats(t_dec)
    e2e = layer["mean_us"] + feat["mean_us"] + clf_s["mean_us"] + dec["mean_us"]
    return {
        "n_samples": len(feats), "warmup": warmup, "n_features": len(content_idx),
        "stages_us": {"layer": layer, "feature": feat,
                      "classification": clf_s, "decision": dec},
        "extraction_us_per_pkt": layer["mean_us"] + feat["mean_us"],
        "inference_us_per_pkt": clf_s["mean_us"] + dec["mean_us"],
        "end_to_end_us_per_pkt": e2e,
        "throughput_pps": 1e6 / e2e,
    }
