"""Paridade em gama: FeatureStreamer de referência da C1 (scapy RawPcapReader, extract_ext.py,
results/bytemodels.npz) contra as 16 colunas de extrai.py, nos N primeiros pacotes de cada captura."""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import caminhos as K  # noqa: E402
import os
import sys

import numpy as np

R = K.REPO
sys.path.insert(0, os.path.join(R, "src"))
from scapy.utils import RawPcapReader  # noqa: E402
import someip  # noqa: E402
import extract  # noqa: E402
import extract_ext  # noqa: E402
import bytemodel  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 200000
d = np.load(os.path.join(K.C1_ART, "bytemodels.npz"))
models = {}
for k in extract.L:
    m = bytemodel.ByteModel(extract.L[k], 1.0)
    m.logP = d[k]
    models[k] = m
for cap in sys.argv[2:]:
    st = extract_ext.FeatureStreamer()
    ref = []
    for raw, meta in RawPcapReader(os.path.join(K.GAMA_DIR, cap, "scn.pcap")):
        p = someip.parse(raw, extract._ts(meta))
        if p is None:
            continue
        ref.append(st.step(p, models))
        if len(ref) == N:
            break
    ref = np.asarray(ref, dtype=np.float32)
    X = np.load(os.path.join(K.FEATS, "gama", cap + ".X.npy"), mmap_mode="r")[:len(ref), :16]
    print("%-12s %d pacotes  linhas iguais %.6f  max|dif| %.3g" % (
        cap, len(ref), float(np.mean(np.all(ref == X, axis=1))), float(np.abs(ref - X).max())), flush=True)
