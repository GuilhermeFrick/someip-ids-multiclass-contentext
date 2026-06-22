"""Extrator/rotulador por-pacote a partir dos PCAPs do Kim.

Pipeline:
  1) fit dos modelos de bytes (SOME/IP, SD, TCP/UDP) no tráfego BENIGNO;
  2) varredura de cada PCAP, mantendo estado por-fluxo (mesmo IP+portas) para as features
     relacionais (intervalo, mudança de payload/length), e rotulando por assinatura;
  3) concatena, normaliza (min-max) e salva X (N,12), y_bin (N,), y_multi (N,).

As 12 colunas (ver docs/mapa-features.md):
  0 ip_time_interval   3 l4_loglik      6 l4_entropy      9  l4_change
  1 someip_loglik      4 someip_entropy 7 someip_change   10 ip_len_change
  2 sd_loglik          5 sd_entropy     8 sd_change       11 l4_len_change
"""
from __future__ import annotations

import argparse
import os

import numpy as np
from scapy.utils import RawPcapReader

import someip
import labeler
from bytemodel import ByteModel, hamming

FEATURE_NAMES = [
    "ip_time_interval",
    "someip_loglik", "sd_loglik", "l4_loglik",
    "someip_entropy", "sd_entropy", "l4_entropy",
    "someip_change", "sd_change", "l4_change",
    "ip_len_change", "l4_len_change",
]

# comprimento fixo do modelo de bytes por tipo (ver docs/mapa-features.md)
L = {"someip": 64, "sd": 80, "l4": 64}

PCAP_DIR_DEFAULT = "data/pcap"   # baixados por scripts/download_pcaps.py
ATTACK_FILES = {
    "dos_noti_flood.pcap": labeler.DOS,
    "fuzzy_sd_offer_rand_noti(1).pcap": labeler.FUZZY,
    "fuzzy_sd_offer_rand_noti(2).pcap": labeler.FUZZY,
    "fuzzy_sd_offer_rand_noti(3).pcap": labeler.FUZZY,
    "mitm_multi_attacker.pcap": labeler.MITM_MULTI,
    "mitm_single_attacker.pcap": labeler.MITM_SINGLE,
}
BENIGN_FILE = "benign_traffic.pcap"


def _ts(meta) -> float:
    try:
        return meta.sec + meta.usec * 1e-6
    except Exception:
        try:
            return meta[0] + meta[1] * 1e-6
        except Exception:
            return 0.0


def fit_bytemodels(pcap_dir: str, alpha: float = 1.0, max_packets: int | None = None):
    """Treina os 3 modelos de bytes no tráfego benigno e coleta o conjunto de IPs de
    origem benignos (usado para identificar o nó atacante em cada cenário).
    Retorna (models, benign_src_ips)."""
    models = {k: ByteModel(L[k], alpha) for k in L}
    benign_ips = set()
    n = 0
    for raw, meta in RawPcapReader(os.path.join(pcap_dir, BENIGN_FILE)):
        n += 1
        if max_packets and n > max_packets:
            break
        p = someip.parse(raw)
        if p is None:
            continue
        benign_ips.add(p.src)
        if p.pl_l4:
            models["l4"].update(p.pl_l4)
        if p.is_sd and p.pl_sd:
            models["sd"].update(p.pl_sd)
        elif p.pl_someip:
            models["someip"].update(p.pl_someip)
    for m in models.values():
        m.finalize()
    return models, benign_ips


def extract_file(path: str, models: dict, attack_type: int = labeler.NORMAL,
                 benign_ips: set | None = None, max_packets: int | None = None):
    """Extrai features+rótulos de um PCAP. `attack_type` é o cenário do arquivo
    (NORMAL para o benigno). O nó atacante é identificado como o IP de origem ausente
    do tráfego benigno (`benign_ips`); pacotes do atacante recebem o rótulo do cenário,
    o resto (fundo benigno) fica como NORMAL.
    Retorna (X[list], y_multi[list], attacker_ips[set])."""
    last = {}            # flow_key -> dict(ts, ip_len, l4, someip, sd)
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
        fk = someip.flow_key(p)
        st = last.get(fk)

        # --- features relacionais ---
        if st is None:
            iat = 0.0
            ip_len_chg = 0
            l4_len_chg = 0
            someip_chg = sd_chg = l4_chg = 0
        else:
            iat = p.ts - st["ts"]
            ip_len_chg = p.ip_len - st["ip_len"]
            l4_len_chg = len(p.pl_l4) - len(st["l4"])
            l4_chg = hamming(p.pl_l4, st["l4"])
            someip_chg = hamming(p.pl_someip, st["someip"]) if (p.pl_someip or st["someip"]) else 0
            sd_chg = hamming(p.pl_sd, st["sd"]) if (p.pl_sd or st["sd"]) else 0

        # --- features de payload ---
        someip_ll = models["someip"].loglik(p.pl_someip) if p.pl_someip else 0.0
        sd_ll = models["sd"].loglik(p.pl_sd) if p.pl_sd else 0.0
        l4_ll = models["l4"].loglik(p.pl_l4) if p.pl_l4 else 0.0
        someip_h = models["someip"].cross_entropy(p.pl_someip) if p.pl_someip else 0.0
        sd_h = models["sd"].cross_entropy(p.pl_sd) if p.pl_sd else 0.0
        l4_h = models["l4"].cross_entropy(p.pl_l4) if p.pl_l4 else 0.0

        X.append((iat, someip_ll, sd_ll, l4_ll, someip_h, sd_h, l4_h,
                  someip_chg, sd_chg, l4_chg, ip_len_chg, l4_len_chg))

        # --- rótulo: pacote vindo do nó atacante (IP ausente no benigno) ---
        atk = labeler.NORMAL
        if attack_type != labeler.NORMAL and p.src not in benign_ips:
            atk = attack_type
            attacker_ips.add(p.src)
        ymul.append(atk)

        last[fk] = {"ts": p.ts, "ip_len": p.ip_len, "l4": p.pl_l4,
                    "someip": p.pl_someip, "sd": p.pl_sd}
    return X, ymul, attacker_ips


def run(pcap_dir: str, out_dir: str, max_packets: int | None = None, alpha: float = 1.0):
    os.makedirs(out_dir, exist_ok=True)
    print(f"[1/3] treinando modelos de bytes no benigno (L={L}, alpha={alpha})...")
    models, benign_ips = fit_bytemodels(pcap_dir, alpha, max_packets)
    print(f"      IPs benignos: {len(benign_ips)}")

    Xall, yall = [], []
    files = [(BENIGN_FILE, labeler.NORMAL)] + list(ATTACK_FILES.items())
    for fname, atk_type in files:
        path = os.path.join(pcap_dir, fname)
        if not os.path.exists(path):
            print(f"  [skip] {fname} ausente")
            continue
        X, ymul, attackers = extract_file(path, models, atk_type, benign_ips, max_packets)
        Xall.extend(X)
        yall.extend(ymul)
        atk = sum(1 for v in ymul if v != labeler.NORMAL)
        att = " atacante=" + ",".join(sorted(attackers)) if attackers else ""
        print(f"  {fname:38} pkts={len(ymul):>8}  ataque={atk:>8} ({100*atk/max(len(ymul),1):.1f}%){att}")

    X = np.asarray(Xall, dtype=np.float64)
    ym = np.asarray(yall, dtype=np.int64)
    yb = (ym != labeler.NORMAL).astype(np.int64)

    # --- min-max (Eq. 8), por coluna ---
    print("[2/3] normalizando (min-max por coluna)...")
    xmin = X.min(axis=0)
    xmax = X.max(axis=0)
    rng = np.where(xmax > xmin, xmax - xmin, 1.0)
    Xn = ((X - xmin) / rng).astype(np.float32)

    print("[3/3] salvando...")
    np.savez_compressed(os.path.join(out_dir, "X.npz"), a=Xn)
    np.savez_compressed(os.path.join(out_dir, "y_bin.npz"), a=yb)
    np.savez_compressed(os.path.join(out_dir, "y_multi.npz"), a=ym)
    np.save(os.path.join(out_dir, "minmax.npy"), np.vstack([xmin, xmax]))
    print(f"OK: X={Xn.shape}  ataque={100*yb.mean():.2f}%  -> {out_dir}")
    for c, v in zip(["normal", "dos", "fuzzy", "mitm_single", "mitm_multi"],
                    np.bincount(ym, minlength=5)):
        print(f"   {c:12} {v}")
    return Xn, yb, ym


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir", default=PCAP_DIR_DEFAULT)
    ap.add_argument("--out", default="data/ours")
    ap.add_argument("--max-packets", type=int, default=None,
                    help="limite por arquivo (para desenvolvimento)")
    ap.add_argument("--alpha", type=float, default=1.0)
    a = ap.parse_args()
    run(a.pcap_dir, a.out, a.max_packets, a.alpha)
