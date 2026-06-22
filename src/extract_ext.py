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

RELAY_SERVICE = 0x100B

FEATURE_NAMES = [
    # core (12)
    "ip_time_interval", "someip_loglik", "sd_loglik", "l4_loglik",
    "someip_entropy", "sd_entropy", "l4_entropy",
    "someip_change", "sd_change", "l4_change", "ip_len_change", "l4_len_change",
    # ext (9)
    "repeat_rate", "someip_len", "l4_len", "src_pkt_rate", "src_payload_div",
    "is_sd", "src_service_div", "is_relay", "src_clientid_div",
]


def extract_file(path, models, attack_type=labeler.NORMAL, benign_ips=None, max_packets=None):
    last = {}
    benign_ips = benign_ips or set()
    attacker_ips = set()
    # estado das features comportamentais
    recent_pld = defaultdict(lambda: deque(maxlen=5))      # por fluxo
    src_ts = defaultdict(lambda: deque(maxlen=1000))       # por src
    src_pld = defaultdict(lambda: deque(maxlen=1000))      # por src
    src_svc = defaultdict(lambda: deque(maxlen=100))       # por src
    src_cid = defaultdict(lambda: deque(maxlen=100))       # por src
    X, ymul = [], []
    n = 0
    for raw, meta in RawPcapReader(path):
        n += 1
        if max_packets and n > max_packets:
            break
        p = someip.parse(raw, _ts(meta))
        if p is None:
            continue
        fk = someip.flow_key(p)
        st = last.get(fk)

        # --- core relacionais ---
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

        someip_ll = models["someip"].loglik(p.pl_someip) if p.pl_someip else 0.0
        sd_ll = models["sd"].loglik(p.pl_sd) if p.pl_sd else 0.0
        l4_ll = models["l4"].loglik(p.pl_l4) if p.pl_l4 else 0.0
        someip_h = models["someip"].cross_entropy(p.pl_someip) if p.pl_someip else 0.0
        sd_h = models["sd"].cross_entropy(p.pl_sd) if p.pl_sd else 0.0
        l4_h = models["l4"].cross_entropy(p.pl_l4) if p.pl_l4 else 0.0

        # --- ext comportamentais ---
        # f13 repeat rate (fração dos últimos 5 payloads SOME/IP iguais ao atual)
        h = recent_pld[fk]
        repeat_rate = (sum(1 for q in h if q == p.pl_someip) / len(h)) if (h and p.pl_someip) else 0.0
        h.append(p.pl_someip)
        # f15/f16 comprimentos
        someip_len = float(len(p.pl_someip))
        l4_len = float(len(p.pl_l4))
        # f17 taxa de pacotes por src (janela 1000)
        wt = src_ts[p.src]; wt.append(p.ts)
        if len(wt) >= 2:
            d = wt[-1] - wt[0]
            src_pkt_rate = (len(wt) - 1) / d if d > 0 else float(len(wt))
        else:
            src_pkt_rate = 0.0
        # f18 diversidade de payload por src
        wp = src_pld[p.src]
        if p.pl_someip:
            wp.append(p.pl_someip)
        src_payload_div = (len(set(wp)) / len(wp)) if len(wp) > 1 else 0.0
        # f19 is_sd
        is_sd = 1.0 if p.is_sd else 0.0
        # f20 diversidade de serviços por src
        ws = src_svc[p.src]
        if p.service_id >= 0:
            ws.append(p.service_id)
        src_service_div = float(len(set(ws))) if ws else 1.0
        # f21 relay service
        is_relay = 1.0 if p.service_id == RELAY_SERVICE else 0.0
        # f22 diversidade de client_id em REQUESTs (msg_type < 0x80) por src
        wc = src_cid[p.src]
        if p.client_id >= 0 and 0 <= p.msg_type < 0x80:
            wc.append(p.client_id)
        src_clientid_div = float(len(set(wc))) if wc else 1.0

        X.append((iat, someip_ll, sd_ll, l4_ll, someip_h, sd_h, l4_h,
                  someip_chg, sd_chg, l4_chg, ip_len_chg, l4_len_chg,
                  repeat_rate, someip_len, l4_len, src_pkt_rate, src_payload_div,
                  is_sd, src_service_div, is_relay, src_clientid_div))

        atk = labeler.NORMAL
        if attack_type != labeler.NORMAL and p.src not in benign_ips:
            atk = attack_type
            attacker_ips.add(p.src)
        ymul.append(atk)

        last[fk] = {"ts": p.ts, "ip_len": p.ip_len, "l4": p.pl_l4,
                    "someip": p.pl_someip, "sd": p.pl_sd}
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
