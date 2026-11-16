#!/usr/bin/env python3
"""Extração única de todas as features (C1, SD, comportamento, eco, novas) e metadados.

Um PCAP -> <out>.X.npy (float32, N x len(COLS)) e <out>.meta.npz. Mesmo conjunto de pacotes da
C1 (someip.parse(raw) != None), mesma ordem. As features da C1 usam o modelo de bytes do Kim
(colunas sem prefixo) e, em colunas "bmB:", as 6 de modelo de bytes com o modelo da bancada.

Uso: extrai.py --manifest manifest.json --jobs 6 [--so nome1,nome2] [--max N]
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
import extract_ext  # noqa: E402
import bytemodel  # noqa: E402
import fast_streamer as fs  # noqa: E402
from sd_features import SdStreamer, SD_NOMES  # noqa: E402
from comport_features import CompStreamer, COMP_NOMES  # noqa: E402
from eco_features import EcoStreamer, ECO_NOMES  # noqa: E402
from novas import NovasStreamer, NOVAS_NOMES  # noqa: E402
from pcapio import ler  # noqa: E402

C1 = list(extract_ext.FEATURE_NAMES)
BM = ["someip_loglik", "sd_loglik", "l4_loglik", "someip_entropy", "sd_entropy", "l4_entropy"]
COLS = C1 + ["bmB:" + n for n in BM] + SD_NOMES + COMP_NOMES + ECO_NOMES + NOVAS_NOMES


def carrega_bm(npz):
    d = np.load(npz)
    out = {}
    for k in extract.L:
        m = bytemodel.ByteModel(extract.L[k], 1.0)
        m.logP = d[k]
        out[k] = m
    return out


def ip_u32(s):
    a = s.split(".")
    return (int(a[0]) << 24) | (int(a[1]) << 16) | (int(a[2]) << 8) | int(a[3])


def uma(t):
    out = t["out"]
    if os.path.exists(out + ".meta.npz") and not t.get("forca"):
        return t["name"], "cache"
    t0 = time.time()
    bmk = fs.memoriza(carrega_bm(os.path.join(K.C1_ART, "bytemodels.npz")))
    bmb = fs.memoriza(carrega_bm(os.path.join(K.ARTEFATOS, "bm-bancada.npz")))
    st = fs.classe_rapida(extract_ext)()
    sds, cps, ecs, nvs = SdStreamer(), CompStreamer(), EcoStreamer(), NovasStreamer()
    macs = {k.lower(): v for k, v in t.get("macs", {}).items()}
    atk_ip, benign_ips = t.get("ip_atk_class", 0), set(t.get("benign_ips", []))
    blocos, X = [], []
    M = {k: [] for k in ("y_mac", "y_ip", "ack", "ts", "src", "mac", "is_sd", "msg_type", "svc",
                         "method", "proto")}
    n = 0
    for ts, raw in ler(t["pcap"]):
        p = someip.parse(raw, ts)
        if p is None:
            continue
        n += 1
        if t.get("max") and n > t["max"]:
            break
        f = st.step(p, bmk)
        g = (bmb["someip"].loglik(p.pl_someip) if p.pl_someip else 0.0,
             bmb["sd"].loglik(p.pl_sd) if p.pl_sd else 0.0,
             bmb["l4"].loglik(p.pl_l4) if p.pl_l4 else 0.0,
             bmb["someip"].cross_entropy(p.pl_someip) if p.pl_someip else 0.0,
             bmb["sd"].cross_entropy(p.pl_sd) if p.pl_sd else 0.0,
             bmb["l4"].cross_entropy(p.pl_l4) if p.pl_l4 else 0.0)
        X.append(tuple(f) + g + sds.step(raw, p.src, p.dst, p.service_id, p.ts) + cps.step(p)
                 + ecs.step(p) + nvs.step(p, raw))
        mac = bytes(raw[6:12])
        M["y_mac"].append(macs.get(mac.hex(":"), 0))
        M["y_ip"].append(atk_ip if (atk_ip and p.src not in benign_ips) else 0)
        M["ack"].append(p.proto == 6 and len(p.pl_l4) == 0)
        M["ts"].append(ts)
        M["src"].append(ip_u32(p.src))
        M["mac"].append(int.from_bytes(mac, "big"))
        M["is_sd"].append(p.is_sd)
        M["msg_type"].append(p.msg_type)
        M["svc"].append(p.service_id)
        M["method"].append(p.method_id)
        M["proto"].append(p.proto)
        if len(X) == 200000:
            blocos.append(np.asarray(X, dtype=np.float32))
            X = []
    if X or not blocos:
        blocos.append(np.asarray(X, dtype=np.float32).reshape(-1, len(COLS)))
    Xa = np.concatenate(blocos)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    np.save(out + ".X.npy", Xa)
    tipos = {"y_mac": np.int8, "y_ip": np.int8, "ack": bool, "ts": np.float64, "src": np.uint32,
             "mac": np.uint64, "is_sd": bool, "msg_type": np.int16, "svc": np.int32, "method": np.int32,
             "proto": np.int8}
    np.savez(out + ".meta.npz", **{k: np.asarray(v, dtype=tipos[k]) for k, v in M.items()})
    return t["name"], "%d pacotes, %.0f s" % (len(Xa), time.time() - t0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--so", default=None, help="nomes (ou prefixos terminados em /) separados por vírgula")
    ap.add_argument("--max", type=int, default=None)
    ap.add_argument("--sufixo", default="")
    a = ap.parse_args()
    tarefas = json.load(open(a.manifest))
    if a.so:
        sel = a.so.split(",")
        tarefas = [t for t in tarefas if any(t["name"] == s or (s.endswith("/") and t["name"].startswith(s))
                                             for s in sel)]
    for t in tarefas:
        if a.max:
            t["max"] = a.max
        if a.sufixo:
            t["out"] += a.sufixo
    json.dump(COLS, open(os.path.join(BASE, "feats", "cols.json"), "w"))
    tarefas.sort(key=lambda t: -os.path.getsize(t["pcap"]))
    t0 = time.time()
    with Pool(a.jobs) as pool:
        for nome, msg in pool.imap_unordered(uma, tarefas):
            print("[%6.0f s] %-40s %s" % (time.time() - t0, nome, msg), flush=True)


if __name__ == "__main__":
    main()
