#!/usr/bin/env python3
"""Relatorio por classe (precisao/recall/F1) com o modelo novo, e salva model_16.json."""
import sys, json
import numpy as np
sys.path.insert(0, "src")
import pipeline
from sklearn.metrics import classification_report
from xgboost import XGBClassifier

z = np.load("/home/ubuntu/model-sweep/features.npz", allow_pickle=True)
Xn, y, counts = z["Xn"], z["y"], z["counts"].tolist()
itr, ite = pipeline.temporal_split(counts)
yte = y[ite]

out = {}
for idx, lab in [(list(range(12)), "12feat"), (pipeline.CONTENT_EXT, "16feat")]:
    clf = XGBClassifier(**pipeline.model_params())
    clf.fit(Xn[np.ix_(itr, idx)], y[itr])
    rep = classification_report(yte, clf.predict(Xn[np.ix_(ite, idx)]),
                                target_names=pipeline.CLASSES, digits=4,
                                output_dict=True)
    out[lab] = rep
    if lab == "16feat":
        clf.get_booster().save_model("results/model_16.json")
        print("[ok] results/model_16.json salvo com os parametros novos")

json.dump(out, open("results/perclass.json", "w"), indent=2)

print()
print("16 FEATURES".ljust(14), "precisao".rjust(10), "recall".rjust(10), "F1".rjust(10))
for c in pipeline.CLASSES + ["macro avg"]:
    r = out["16feat"][c]
    print(c.ljust(14), f"{r['precision']:10.4f}", f"{r['recall']:10.4f}", f"{r['f1-score']:10.4f}")

print()
print("ABLACAO 12 x 16 (F1)")
print("classe".ljust(14), "12feat".rjust(10), "16feat".rjust(10))
for c in pipeline.CLASSES:
    print(c.ljust(14), f"{out['12feat'][c]['f1-score']:10.4f}",
          f"{out['16feat'][c]['f1-score']:10.4f}")
print("macro".ljust(14), f"{out['12feat']['macro avg']['f1-score']:10.4f}",
      f"{out['16feat']['macro avg']['f1-score']:10.4f}")
