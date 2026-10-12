"""Extrator ESTENDIDO: as 12 features fiéis ao Kim + 9 features comportamentais
inspiradas no repo `detection` (f13–f22). Mesmo rotulador por nó atacante e mesmo
split de origem (PCAPs do Kim), para podermos testar se features mais ricas resolvem o
gargalo (fuzzy/mitm_multi) — e, principalmente, se ajudam no zero-day ou só memorizam.

Reaproveita o parser (`someip.py`) e os modelos de bytes (`extract.fit_bytemodels`).

21 colunas:
  core (12): ip_time_interval, someip_loglik, sd_loglik, l4_loglik,
             someip_entropy, sd_entropy, l4_entropy,
             someip_change, sd_change, l4_change, ip_len_change, l4_len_change
  ext  (9):  repeat_rate, someip_len, l4_len, src_pkt_rate, src_payload_div,
             is_sd, src_service_div, is_relay, src_clientid_div

⚠️ src_pkt_rate (f17) e is_relay (f21) são quase-definicionais de alguns ataques — boas
in-scope, fracas para generalizar (ver docs/analise-critica-detection... e relatorio-zeroday).

Reproduzir: python src/extract_ext.py --out data/ours_ext
"""
from __future__ import annotations

import argparse
import os
from collections import defaultdict, deque

import numpy as np
from scapy.utils import RawPcapReader

import someip
import labeler
from bytemodel import hamming
from extract import (fit_bytemodels, BENIGN_FILE, ATTACK_FILES, PCAP_DIR_DEFAULT,
                     L, _ts)

FEATURE_NAMES = [
    # 12 do baseline (conteúdo + temporização, por camada)
    "ip_time_interval", "someip_loglik", "sd_loglik", "l4_loglik",
    "someip_entropy", "sd_entropy", "l4_entropy",
    "someip_change", "sd_change", "l4_change", "ip_len_change", "l4_len_change",
    # 4 propostas (comportamentais): payload repetition, absolute size (2), source diversity
    "repeat_rate", "someip_len", "l4_len", "src_payload_div",
]


class FeatureStreamer:
    """Extração com estado, pacote a pacote (as 16 features: 12 do baseline + 4 propostas).

    Fonte única: `extract_file` (lote) e `src/latency.py` (por pacote, p/ medir tempo)
    usam esta classe, de modo que o cálculo das 16 features é idêntico nos dois.
    `step(p, models)` calcula o vetor do pacote e ATUALIZA o estado interno (janelas
    por fluxo e por origem), devolvendo a tupla de 16 features.
    """

    def __init__(self):
        self.last = {}                                          # por fluxo (flow_key)
        self.recent_pld = defaultdict(lambda: deque(maxlen=5))  # por fluxo  (repeat_rate)
        self.src_pld = defaultdict(lambda: deque(maxlen=1000))  # por origem (src_payload_div)

    def step(self, p, models) -> tuple:
        fk = someip.flow_key(p)
        st = self.last.get(fk)

        # --- 12 do baseline: temporização e mudanças ---
        if st is None:
            iat = 0.0; ip_len_chg = 0; l4_len_chg = 0
            someip_chg = sd_chg = l4_chg = 0
        else:
            iat = p.ts - st["ts"]
            ip_len_chg = p.ip_len - st["ip_len"]
            l4_len_chg = len(p.pl_l4) - len(st["l4"])
            l4_chg = hamming(p.pl_l4, st["l4"])
            someip_chg = hamming(p.pl_someip, st["someip"]) if (p.pl_someip or st["someip"]) else 0
            sd_chg = hamming(p.pl_sd, st["sd"]) if (p.pl_sd or st["sd"]) else 0

        # --- 12 do baseline: conteúdo (byte-model) ---
        someip_ll = models["someip"].loglik(p.pl_someip) if p.pl_someip else 0.0
        sd_ll = models["sd"].loglik(p.pl_sd) if p.pl_sd else 0.0
        l4_ll = models["l4"].loglik(p.pl_l4) if p.pl_l4 else 0.0
        someip_h = models["someip"].cross_entropy(p.pl_someip) if p.pl_someip else 0.0
        sd_h = models["sd"].cross_entropy(p.pl_sd) if p.pl_sd else 0.0
        l4_h = models["l4"].cross_entropy(p.pl_l4) if p.pl_l4 else 0.0

        # --- 4 propostas ---
        h = self.recent_pld[fk]
        repeat_rate = (sum(1 for q in h if q == p.pl_someip) / len(h)) if (h and p.pl_someip) else 0.0  # payload repetition
        h.append(p.pl_someip)
        someip_len = float(len(p.pl_someip))                     # absolute size (1/2)
        l4_len = float(len(p.pl_l4))                             # absolute size (2/2)
        wp = self.src_pld[p.src]
        if p.pl_someip:
            wp.append(p.pl_someip)
        src_payload_div = (len(set(wp)) / len(wp)) if len(wp) > 1 else 0.0                              # source diversity

        self.last[fk] = {"ts": p.ts, "ip_len": p.ip_len, "l4": p.pl_l4,
                         "someip": p.pl_someip, "sd": p.pl_sd}
        return (iat, someip_ll, sd_ll, l4_ll, someip_h, sd_h, l4_h,
                someip_chg, sd_chg, l4_chg, ip_len_chg, l4_len_chg,
                repeat_rate, someip_len, l4_len, src_payload_div)


def extract_file(path, models, attack_type=labeler.NORMAL, benign_ips=None, max_packets=None):
    """Extrai as 16 features de todos os pacotes de um PCAP (via FeatureStreamer) e
    atribui o rótulo por nó atacante (origem fora do conjunto benigno)."""
    streamer = FeatureStreamer()
    benign_ips = benign_ips or set()
    attacker_ips = set()
    X, ymul = [], []
    n = 0
    for raw, meta in RawPcapReader(path):
        n += 1
        if max_packets and n > max_packets:
            break
        p = someip.parse(raw, _ts(meta))
        if p is None:
            continue
        X.append(streamer.step(p, models))
        atk = labeler.NORMAL
        if attack_type != labeler.NORMAL and p.src not in benign_ips:
            atk = attack_type
            attacker_ips.add(p.src)
        ymul.append(atk)
    return X, ymul, attacker_ips


def run(pcap_dir, out_dir, max_packets=None, alpha=1.0):
    os.makedirs(out_dir, exist_ok=True)
    print(f"[1/3] modelos de bytes no benigno (L={L})...")
    models, benign_ips = fit_bytemodels(pcap_dir, alpha, max_packets)
    print(f"      IPs benignos: {len(benign_ips)}")

    Xall, yall = [], []
    files = [(BENIGN_FILE, labeler.NORMAL)] + list(ATTACK_FILES.items())
    for fname, atk_type in files:
        path = os.path.join(pcap_dir, fname)
        if not os.path.exists(path):
            print(f"  [skip] {fname}")
            continue
        X, ymul, attackers = extract_file(path, models, atk_type, benign_ips, max_packets)
        Xall.extend(X); yall.extend(ymul)
        atk = sum(1 for v in ymul if v != labeler.NORMAL)
        print(f"  {fname:38} pkts={len(ymul):>8} ataque={atk:>8} ({100*atk/max(len(ymul),1):.1f}%)")

    X = np.asarray(Xall, dtype=np.float64)
    ym = np.asarray(yall, dtype=np.int64)
    yb = (ym != labeler.NORMAL).astype(np.int64)

    print("[2/3] min-max por coluna...")
    xmin = X.min(axis=0); xmax = X.max(axis=0)
    rng = np.where(xmax > xmin, xmax - xmin, 1.0)
    Xn = ((X - xmin) / rng).astype(np.float32)

    print("[3/3] salvando...")
    np.savez_compressed(os.path.join(out_dir, "X.npz"), a=Xn)
    np.savez_compressed(os.path.join(out_dir, "y_bin.npz"), a=yb)
    np.savez_compressed(os.path.join(out_dir, "y_multi.npz"), a=ym)
    # artefatos de referência p/ aplicar a MESMA extração/normalização a outros PCAPs
    # (necessário para o teste de transferência — Experimento A do benchmark)
    np.save(os.path.join(out_dir, "minmax.npy"), np.vstack([xmin, xmax]))
    np.savez_compressed(os.path.join(out_dir, "bytemodels.npz"),
                        someip=models["someip"].logP, sd=models["sd"].logP, l4=models["l4"].logP)
    import json
    json.dump(FEATURE_NAMES, open(os.path.join(out_dir, "feature_names.json"), "w"), indent=2)
    print(f"OK: X={Xn.shape} ataque={100*yb.mean():.2f}% -> {out_dir}")
    for c, v in zip(["normal", "dos", "fuzzy", "mitm_single", "mitm_multi"],
                    np.bincount(ym, minlength=5)):
        print(f"   {c:12} {v}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir", default=PCAP_DIR_DEFAULT)
    ap.add_argument("--out", default="data/ours_ext")
    ap.add_argument("--max-packets", type=int, default=None)
    ap.add_argument("--alpha", type=float, default=1.0)
    a = ap.parse_args()
    run(a.pcap_dir, a.out, a.max_packets, a.alpha)
