"""Quebra do FP da matriz C1 por origem (IP) e classe prevista: beta->beta no MITM multi (rótulo IP)
e beta->gama no benigno de gama."""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import caminhos as K  # noqa: E402
import json
import os

import numpy as np
import xgboost as xgb

R = K.REPO
BASE = K.WORK
os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
CL = ["normal", "dos", "fuzzy", "mitm_single", "mitm_multi"]
b = xgb.Booster()
b.load_model(os.path.join(K.C1_ART, "model_16.json"))
mm = np.load(os.path.join(K.C1_ART, "minmax.npy"))
rng = np.where(mm[1] > mm[0], mm[1] - mm[0], 1.0)


def quebra(X, y, src, rot):
    p = b.predict(xgb.DMatrix(((X.astype(np.float64) - mm[0]) / rng).astype(np.float32))).argmax(1)
    nor = y == 0
    out = {}
    for s in np.unique(src[nor]):
        k = nor & (src == s)
        fp = p[k] > 0
        out[".%d" % (s & 255)] = {"normais": int(k.sum()), "fp": int(fp.sum()), "taxa": float(fp.mean()),
                                  "prev": {CL[c]: int(np.sum(p[k] == c)) for c in range(1, 5) if np.sum(p[k] == c)}}
    print(rot, json.dumps(out, indent=0))
    return out


res = {}
for dom, nome, lab in (("kim", "mitm_multi", "y_ip"), ("gama", "benign", "y_mac")):
    X = np.load(os.path.join(BASE, "feats", dom, nome + ".X.npy"), mmap_mode="r")
    m = np.load(os.path.join(BASE, "feats", dom, nome + ".meta.npz"))
    c = int(len(X) * 0.7)
    res["%s/%s" % (dom, nome)] = quebra(np.array(X[c:, :16]), m[lab][c:].astype(np.int64), m["src"][c:], dom + "/" + nome)
json.dump(res, open(os.path.join(BASE, "results", "matriz_fp_origem.json"), "w"), indent=1)
