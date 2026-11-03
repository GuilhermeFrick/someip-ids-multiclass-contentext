"""exp3: as 12 features fiéis ao Kim + as 4 propostas da C1, multiclasse (5 classes).

As 4 da C1 (repeat_rate, someip_len, l4_len, src_payload_div) são calculadas exatamente como
em src/extract_ext.py (FeatureStreamer), mas sobre as MESMAS linhas do extrator do Kim
(pacotes TCP/UDP, sem o 1º de cada PCAP), para que as 12 colunas sejam as do Kim e a única
diferença entre os modelos seja o acréscimo das 4.

  e3_kim       : 16 features, rótulo do Kim, divisão do Kim (par/ímpar)
  e3_temporal  : 16 features, rótulo do Kim, divisão temporal 70/30
  e3b_mac12    : 12 features, rótulo pelo MAC de origem, divisão temporal 70/30
  e3b_mac16    : 16 features, rótulo pelo MAC de origem, divisão temporal 70/30

O rótulo pelo MAC marca como ataque tudo o que sai de um MAC ausente do benign_traffic.pcap
(inclui o TCP interno do relay no MITM multi, que o Kim deixa como normal).

Uso (someip-parity:1): python3 scripts/kim_c1_multiclass.py --pcap /d --out /work/kimf
"""
import argparse
import json
import os
import sys
from collections import Counter, defaultdict, deque
from multiprocessing import Pool

import numpy as np

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, "..", "src"))
sys.path.insert(0, AQUI)
import kim_faithful as kf  # noqa: E402
import someip  # noqa: E402
from kim_validate import FILES  # noqa: E402
from kim_multiclass import FAMILIA, avalia, split_kim, split_temporal  # noqa: E402

C1_NAMES = ["repeat_rate", "someip_len", "l4_len", "src_payload_div"]


def c1_extra(pcap):
    """As 4 features da C1, uma linha por linha do extrator do Kim."""
    recent = defaultdict(lambda: deque(maxlen=5))      # por fluxo
    src_win = defaultdict(lambda: deque(maxlen=1000))  # por origem
    src_cnt = defaultdict(Counter)                     # distintos da janela, sem refazer o set
    rows, primeiro = [], True
    for ts, raw in kf.read_pcap(pcap):
        if kf.views(raw) is None:
            continue
        p = someip.parse(raw, ts)
        h = recent[someip.flow_key(p)]
        rr = (sum(1 for q in h if q == p.pl_someip) / len(h)) if (h and p.pl_someip) else 0.0
        h.append(p.pl_someip)
        w, c = src_win[p.src], src_cnt[p.src]
        if p.pl_someip:
            if len(w) == w.maxlen:
                velho = w[0]
                c[velho] -= 1
                if not c[velho]:
                    del c[velho]
            w.append(p.pl_someip)
            c[p.pl_someip] += 1
        div = (len(c) / len(w)) if len(w) > 1 else 0.0
        if not primeiro:
            rows.append((rr, len(p.pl_someip), len(p.pl_l4), div))
        primeiro = False
    return np.array(rows, np.float32)


def _extra_cache(args):
    pcap_dir, out, f = args
    cache = os.path.join(out, f + ".c1ext.npy")
    if not os.path.exists(cache):
        np.save(cache, c1_extra(os.path.join(pcap_dir, f)))
    return f


def dados(out, n_feat, rotulo):
    """{arquivo: (X, y)} com 12 ou 16 colunas e rótulo 'kim' ou 'mac'."""
    bmac = {bytes(m) for m in np.load(os.path.join(out, FILES[0] + ".npz"))["mac"]}
    d = {}
    for f in FILES:
        z = np.load(os.path.join(out, f + ".npz"))
        X = z["X"].astype(np.float32)
        if n_feat == 16:
            E = np.load(os.path.join(out, f + ".c1ext.npy"))
            assert len(E) == len(X), (f, len(E), len(X))
            X = np.hstack([X, E])
        y = np.zeros(len(X), np.int64)
        if f in FAMILIA:
            if rotulo == "kim":
                y[np.load(os.path.join(out, f + ".kim_attack_idx.npy"))] = FAMILIA[f]
            else:
                y[np.array([bytes(m) not in bmac for m in z["mac"]])] = FAMILIA[f]
        d[f] = (X, y)
    return d


EXPS = {
    "e3_kim": ("16 features, rótulo do Kim, divisão do Kim (par/ímpar)", 16, "kim", split_kim),
    "e3_temporal": ("16 features, rótulo do Kim, divisão temporal 70/30", 16, "kim", split_temporal),
    "e3b_mac12": ("12 features, rótulo por MAC, divisão temporal 70/30", 12, "mac", split_temporal),
    "e3b_mac16": ("16 features, rótulo por MAC, divisão temporal 70/30", 16, "mac", split_temporal),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--exp", nargs="+", default=list(EXPS))
    a = ap.parse_args()
    with Pool(4) as pool:
        for f in pool.imap_unordered(_extra_cache, [(a.pcap, a.out, f) for f in FILES]):
            print("4 features da C1:", f, flush=True)
    dst = os.path.join(a.out, "kim_c1_multiclass.json")
    res = json.load(open(dst)) if os.path.exists(dst) else []
    for k in a.exp:
        nome, n_feat, rotulo, split = EXPS[k]
        r = avalia(nome, *split(dados(a.out, n_feat, rotulo)))
        r["id"] = k
        res = [x for x in res if x.get("id") != k] + [r]
        json.dump(res, open(dst, "w"), indent=1)


if __name__ == "__main__":
    main()
