#!/usr/bin/env python3
"""Modelo de bytes do domínio gama (CARLA) e as 6 colunas de modelo de bytes com ele ("bmG:").

1. Ajusta o modelo de bytes nos primeiros 70% (pacotes aceitos pelo parser) do benigno de gama,
   ou seja, só na porção de TREINO (a C1 ajustou o do Kim no benigno inteiro; aqui o teste de
   gama fica fora do ajuste). Grava feats/bm-gama.npz.
2. Para cada PCAP pedido, grava <out>.bmG.npy (float32, N x 6), nas mesmas linhas de extrai.py.
3. Para gama, confere o rótulo por MAC (y_mac de extrai.py) contra scn.labels (índice do quadro).

Uso: bm_gama.py --manifest feats/manifest.json --jobs 4 [--so kim/,gama/,bancada/] [--dom gama|parado]
Com --dom parado, o mesmo para o γ-parado: feats/bm-parado.npz e <out>.bmP.npy.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import caminhos as K  # noqa: E402
import argparse
import json
import os
import sys
import time
from multiprocessing import Pool

AQUI = os.path.dirname(os.path.abspath(__file__))
BASE = K.WORK
for d in (K.C1_SRC, K.LIB, AQUI):
    sys.path.insert(0, d)
import numpy as np  # noqa: E402
import someip  # noqa: E402
import extract  # noqa: E402
import bytemodel  # noqa: E402
import fast_streamer as fs  # noqa: E402
from pcapio import ler  # noqa: E402
from extrai import carrega_bm  # noqa: E402

SUFIXO = {"gama": ".bmG.npy", "parado": ".bmP.npy"}
DOM = "gama"
BMG = os.path.join(BASE, "feats", "bm-gama.npz")


def ajusta(pcap):
    n = sum(1 for ts, raw in ler(pcap) if someip.parse(raw, ts) is not None)
    corte = int(n * 0.7)
    models = {k: bytemodel.ByteModel(extract.L[k], 1.0) for k in extract.L}
    i = 0
    for ts, raw in ler(pcap):
        p = someip.parse(raw, ts)
        if p is None:
            continue
        if i >= corte:
            break
        i += 1
        if p.pl_l4:
            models["l4"].update(p.pl_l4)
        if p.is_sd and p.pl_sd:
            models["sd"].update(p.pl_sd)
        elif p.pl_someip:
            models["someip"].update(p.pl_someip)
    for m in models.values():
        m.finalize()
    np.savez_compressed(BMG, someip=models["someip"].logP, sd=models["sd"].logP, l4=models["l4"].logP)
    return n, corte


def uma(t):
    out = t["out"] + SUFIXO[DOM]
    if os.path.exists(out):
        return t["name"], "cache"
    t0 = time.time()
    bm = fs.memoriza(carrega_bm(BMG))
    rot = None
    lab = os.path.join(os.path.dirname(t["pcap"]), "scn.labels")
    if t["dom"] in SUFIXO and os.path.exists(lab):
        rot = {}
        for linha in open(lab):
            a = linha.split()
            if len(a) == 2:
                rot[int(a[0])] = int(a[1])
    G, ylab = [], []
    for i, (ts, raw) in enumerate(ler(t["pcap"])):
        p = someip.parse(raw, ts)
        if p is None:
            continue
        G.append((bm["someip"].loglik(p.pl_someip) if p.pl_someip else 0.0,
                  bm["sd"].loglik(p.pl_sd) if p.pl_sd else 0.0,
                  bm["l4"].loglik(p.pl_l4) if p.pl_l4 else 0.0,
                  bm["someip"].cross_entropy(p.pl_someip) if p.pl_someip else 0.0,
                  bm["sd"].cross_entropy(p.pl_sd) if p.pl_sd else 0.0,
                  bm["l4"].cross_entropy(p.pl_l4) if p.pl_l4 else 0.0))
        if rot is not None:
            ylab.append(rot.get(i, -1))
    G = np.asarray(G, dtype=np.float32).reshape(-1, 6)
    np.save(out, G)
    msg = "%d linhas, %.0f s" % (len(G), time.time() - t0)
    if rot is not None:
        meta = np.load(t["out"] + ".meta.npz")
        ylab = np.asarray(ylab)
        msg += "; y_mac == scn.labels: %s (difere em %d)" % (
            bool(np.array_equal(meta["y_mac"], ylab)), int(np.sum(meta["y_mac"] != ylab)))
    return t["name"], msg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--so", default="kim/,gama/,bancada/")
    ap.add_argument("--dom", default="gama", choices=sorted(SUFIXO),
                    help="domínio cujo benigno ajusta o modelo de bytes (gama: .bmG.npy; parado: .bmP.npy)")
    a = ap.parse_args()
    global DOM, BMG
    DOM, BMG = a.dom, os.path.join(BASE, "feats", "bm-%s.npz" % a.dom)
    T = json.load(open(a.manifest))
    if not os.path.exists(BMG):
        g = [t for t in T if t["name"] == DOM + "/benign"][0]
        print("modelo de bytes %s:" % DOM, ajusta(g["pcap"]), flush=True)
    sel = a.so.split(",")
    T = [t for t in T if any(t["name"].startswith(s) for s in sel)]
    T.sort(key=lambda t: -os.path.getsize(t["pcap"]))
    t0 = time.time()
    with Pool(a.jobs) as pool:
        for nome, msg in pool.imap_unordered(uma, T):
            print("[%6.0f s] %-36s %s" % (time.time() - t0, nome, msg), flush=True)


if __name__ == "__main__":
    main()
