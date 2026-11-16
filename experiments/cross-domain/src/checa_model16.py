"""Confere o artefato results/model_16.json da C1 contra o número publicado (macro-F1 0,9689)."""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import caminhos as K  # noqa: E402
import json
import os
import sys

import numpy as np
import xgboost as xgb
from sklearn.metrics import classification_report

R = K.REPO
sys.path.insert(0, os.path.join(R, "src"))
import pipeline  # noqa: E402

b = xgb.Booster()
b.load_model(os.path.join(K.C1_ART, "model_16.json"))
cfg = json.loads(b.save_config())
tp = cfg["learner"]["gradient_booster"]["tree_train_param"]
print("árvores:", b.num_boosted_rounds(), "rodadas; max_depth", tp.get("max_depth"), "eta", tp.get("eta"))
fpub = os.path.join(R, "results", "features.npz")
if not os.path.exists(fpub):
    print("results/features.npz ausente: a reprodução do 0,9689 é conferida pelo cenário beta->beta de matriz_c1.py")
    sys.exit(0)
z = np.load(fpub, allow_pickle=True)
Xn, y, counts = z["Xn"], z["y"], [int(c) for c in z["counts"]]
itr, ite = pipeline.temporal_split(counts)
pred = b.predict(xgb.DMatrix(Xn[ite])).argmax(1)
rep = classification_report(y[ite], pred, target_names=pipeline.CLASSES, digits=4, output_dict=True, zero_division=0)
print("model_16.json no teste temporal: macro-F1 %.4f" % rep["macro avg"]["f1-score"],
      {c: round(rep[c]["f1-score"], 4) for c in pipeline.CLASSES})
