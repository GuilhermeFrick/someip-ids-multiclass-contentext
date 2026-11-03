"""O "pacote anterior" por fluxo separa DoS de MITM single?

Mesmas linhas, mesmo modelo de bytes, mesmo rótulo (MAC) e mesma divisão temporal 70/30 do
e3b; a única mudança é o "pacote anterior" das colunas 6 a 11 (src/kim_faithful.py, por_fluxo).

  fl12 : 12 features, anterior do mesmo fluxo      (comparar com e3b_mac12, 0,728)
  fl16 : 16 features (+ 4 da C1), idem             (comparar com e3b_mac16, 0,906)

Uso: python3 scripts/kim_fluxo.py --pcap <dir dos PCAPs> --out <dir>
"""
import argparse
import json
import os
import sys
from multiprocessing import Pool

import numpy as np

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, "..", "src"))
sys.path.insert(0, AQUI)
import kim_faithful as kf  # noqa: E402
from kim_validate import FILES  # noqa: E402
from kim_multiclass import FAMILIA, avalia, split_temporal  # noqa: E402
from kim_c1_multiclass import c1_extra  # noqa: E402

MODELS = None


def _init(benign):
    global MODELS
    MODELS = kf.fit_models(benign)


def _um(args):
    pcap_dir, out, f = args
    dst = os.path.join(out, f + ".fluxo.npz")
    if not os.path.exists(dst):
        X, _, macs, _ = kf.extract(os.path.join(pcap_dir, f), MODELS, por_fluxo=True)
        E = c1_extra(os.path.join(pcap_dir, f))
        assert len(E) == len(X)
        np.savez(dst, X=X, E=E, mac=np.frombuffer(b"".join(macs), np.uint8).reshape(-1, 6))
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--exp", nargs="+", default=["fl12", "fl16"])
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    with Pool(len(FILES), initializer=_init, initargs=(os.path.join(a.pcap, FILES[0]),)) as pool:
        for f in pool.imap_unordered(_um, [(a.pcap, a.out, f) for f in FILES]):
            print("extraído:", f, flush=True)
    z = {f: np.load(os.path.join(a.out, f + ".fluxo.npz")) for f in FILES}
    bmac = {bytes(m) for m in z[FILES[0]]["mac"]}
    res = []
    for k, nf in [(k, nf) for k, nf in (("fl12", 12), ("fl16", 16)) if k in a.exp]:
        d = {}
        for f in FILES:
            X = z[f]["X"].astype(np.float32)
            if nf == 16:
                X = np.hstack([X, z[f]["E"]])
            y = np.zeros(len(X), np.int64)
            if f in FAMILIA:
                y[np.array([bytes(m) not in bmac for m in z[f]["mac"]])] = FAMILIA[f]
            d[f] = (X, y)
        r = avalia(f"{nf} features, anterior por fluxo, rótulo por MAC, temporal 70/30", *split_temporal(d),
                   salvar=os.path.join(a.out, "modelo_%s.json" % k))
        r["id"] = k
        res.append(r)
        json.dump(res, open(os.path.join(a.out, "kim_fluxo_%s.json" % k), "w"), indent=1)


if __name__ == "__main__":
    main()
