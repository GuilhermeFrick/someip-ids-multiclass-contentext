#!/usr/bin/env python3
"""Figuras do artigo (narrativa 12 -> 16 features): matriz de confusao, curvas ROC/PR
e metricas macro (ROC-AUC, PR-AUC). Saida em results/figs_artigo/ e results/macro_auc.json."""
from __future__ import annotations
import argparse, os, sys, json
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
import pipeline
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (classification_report, confusion_matrix, roc_curve, auc,
                             precision_recall_curve, average_precision_score, roc_auc_score)
from sklearn.preprocessing import label_binarize
from xgboost import XGBClassifier

CLASSES = pipeline.CLASSES
N = pipeline.N
DISPLAY = {"normal": "normal", "dos": "dos", "fuzzy": "fuzzy",
           "mitm_single": "MITM-single", "mitm_multi": "MITM-multi"}
DNAMES = [DISPLAY.get(c, c) for c in CLASSES]
PARAMS = pipeline.model_params()   # fonte unica: src/pipeline.py

def save_cm(y_te, pred, label, macro, out):
    cm = confusion_matrix(y_te, pred); cmn = cm / cm.sum(1, keepdims=True)
    fig, ax = plt.subplots(figsize=(6, 5)); im = ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(N)); ax.set_yticks(range(N))
    ax.set_xticklabels(DNAMES, rotation=45, ha="right"); ax.set_yticklabels(DNAMES)
    ax.set_xlabel("Previsto"); ax.set_ylabel("Real")
    ax.set_title("Matriz de confusao - %s (macro-F1 %.3f)" % (label, macro))
    for i in range(N):
        for j in range(N):
            ax.text(j, i, "%.1f%%" % (cmn[i, j] * 100), ha="center", va="center",
                    fontsize=8, color="white" if cmn[i, j] > 0.5 else "black")
    fig.colorbar(im, fraction=0.046, pad=0.04); fig.tight_layout()
    fig.savefig("%s/cm_%s.png" % (out, label), dpi=200, bbox_inches="tight"); plt.close(fig)

def save_roc_pr(y_te, proba, label, out):
    yb = label_binarize(y_te, classes=range(N))
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 4.5))
    for i, name in enumerate(DNAMES):
        fpr, tpr, _ = roc_curve(yb[:, i], proba[:, i]); s = max(len(fpr) // 2000, 1)
        a1.plot(fpr[::s], tpr[::s], lw=1.4, label="%s (AUC=%.3f)" % (name, auc(fpr, tpr)))
        pr, rc, _ = precision_recall_curve(yb[:, i], proba[:, i]); s2 = max(len(rc) // 2000, 1)
        a2.plot(rc[::s2], pr[::s2], lw=1.4, label="%s (AP=%.3f)" % (name, average_precision_score(yb[:, i], proba[:, i])))
    a1.plot([0, 1], [0, 1], "k--", lw=.6); a1.set_xlabel("FPR"); a1.set_ylabel("TPR")
    a1.set_title("ROC (one-vs-rest)"); a1.legend(fontsize=8)
    a2.set_xlabel("Recall"); a2.set_ylabel("Precision")
    a2.set_title("Precision-Recall (one-vs-rest)"); a2.legend(fontsize=8)
    fig.tight_layout(); fig.savefig("%s/roc_pr_%s.png" % (out, label), dpi=200, bbox_inches="tight"); plt.close(fig)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir", default="data/pcap")
    ap.add_argument("--out", default="results/figs_artigo")
    ap.add_argument("--max-packets", type=int, default=None)
    ap.add_argument("--cache", default="features.npz",
                    help="cache das features extraidas; a extracao nao depende do modelo, "
                         "entao so precisa rodar uma vez")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    # A extracao custa minutos e NAO depende dos hiperparametros, entao e cacheada:
    # trocar o modelo exige retreinar, nao reextrair.
    if a.cache and os.path.exists(a.cache):
        print(f"[cache] {a.cache}", flush=True)
        z = np.load(a.cache, allow_pickle=True)
        Xn, y, counts = z["Xn"], z["y"], z["counts"].tolist()
    else:
        print("extraindo...", flush=True)
        Xn, y, counts, _t, _m, _mm = pipeline.extract_all(a.pcap_dir, max_packets=a.max_packets)
        if a.cache:
            np.savez_compressed(a.cache, Xn=Xn, y=y,
                                counts=np.array(counts, dtype=object))
            print(f"[cache] salvo em {a.cache}", flush=True)
    itr, ite = pipeline.temporal_split(counts); y_te = y[ite]
    yb = label_binarize(y_te, classes=range(N))
    metrics = {}
    for idx, label in [(list(range(12)), "12feat"), (pipeline.CONTENT_EXT, "16feat")]:
        clf = XGBClassifier(**PARAMS); clf.fit(Xn[np.ix_(itr, idx)], y[itr])
        proba = clf.predict_proba(Xn[np.ix_(ite, idx)]); pred = proba.argmax(1)
        rep = classification_report(y_te, pred, target_names=CLASSES, digits=4, output_dict=True)
        macro = rep["macro avg"]["f1-score"]
        macro_roc = float(roc_auc_score(y_te, proba, average="macro", multi_class="ovr"))
        macro_ap = float(average_precision_score(yb, proba, average="macro"))
        pc_roc = {CLASSES[i]: float(roc_auc_score(yb[:, i], proba[:, i])) for i in range(N)}
        pc_ap = {CLASSES[i]: float(average_precision_score(yb[:, i], proba[:, i])) for i in range(N)}
        save_cm(y_te, pred, label, macro, a.out)
        save_roc_pr(y_te, proba, label, a.out)
        metrics[label] = {"macro_f1": float(macro), "macro_roc_auc": macro_roc,
                          "macro_pr_auc": macro_ap, "per_class_roc_auc": pc_roc,
                          "per_class_pr_auc": pc_ap}
        print("  %s: macro-F1=%.4f  macro ROC-AUC=%.4f  macro PR-AUC=%.4f" %
              (label, macro, macro_roc, macro_ap), flush=True)
    json.dump(metrics, open(os.path.join(a.out, "..", "macro_auc.json"), "w"), indent=2)
    print("DONE_FIGS", flush=True)

if __name__ == "__main__":
    main()
