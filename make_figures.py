#!/usr/bin/env python3
"""Gera as figuras do artigo com a NARRATIVA 12 -> 16 features:
matriz de confusão, curvas ROC/PR e importância, para o detector com 12 features (baseline,
resultado fraco) e com 16 features (12 + 4 propostas). Saída em results/figs_artigo/.

Uso: python make_figures.py --out results/figs_artigo
"""
from __future__ import annotations

import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
import pipeline   # noqa: E402

import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from sklearn.metrics import (classification_report, confusion_matrix, roc_curve, auc,  # noqa: E402
                             precision_recall_curve, average_precision_score)
from sklearn.preprocessing import label_binarize  # noqa: E402
from xgboost import XGBClassifier  # noqa: E402

CLASSES = pipeline.CLASSES
N = pipeline.N
PARAMS = dict(objective="multi:softprob", num_class=N, n_estimators=300, max_depth=8,
              learning_rate=0.3, tree_method="hist", device="cpu", max_bin=256,
              n_jobs=-1, eval_metric="mlogloss")


def save_cm(y_te, pred, label, macro, out):
    cm = confusion_matrix(y_te, pred); cmn = cm / cm.sum(1, keepdims=True)
    fig, ax = plt.subplots(figsize=(6, 5)); im = ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(N)); ax.set_yticks(range(N))
    ax.set_xticklabels(CLASSES, rotation=45, ha="right"); ax.set_yticklabels(CLASSES)
    ax.set_xlabel("Previsto"); ax.set_ylabel("Real")
    ax.set_title("Matriz de confusão — %s (macro-F1 %.3f)" % (label, macro))
    for i in range(N):
        for j in range(N):
            ax.text(j, i, "%.1f%%" % (cmn[i, j] * 100), ha="center", va="center",
                    fontsize=8, color="white" if cmn[i, j] > 0.5 else "black")
    fig.colorbar(im, fraction=0.046, pad=0.04); fig.tight_layout()
    fig.savefig("%s/cm_%s.png" % (out, label), dpi=200, bbox_inches="tight"); plt.close(fig)


def save_roc_pr(y_te, proba, label, out):
    yb = label_binarize(y_te, classes=range(N))
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 4.5))
    for i, name in enumerate(CLASSES):
        fpr, tpr, _ = roc_curve(yb[:, i], proba[:, i]); s = max(len(fpr) // 2000, 1)
        a1.plot(fpr[::s], tpr[::s], lw=1.4, label="%s (AUC=%.3f)" % (name, auc(fpr, tpr)))
        pr, rc, _ = precision_recall_curve(yb[:, i], proba[:, i]); s2 = max(len(rc) // 2000, 1)
        a2.plot(rc[::s2], pr[::s2], lw=1.4, label="%s (AP=%.3f)" % (name, average_precision_score(yb[:, i], proba[:, i])))
    a1.plot([0, 1], [0, 1], "k--", lw=.6); a1.set_xlabel("FPR"); a1.set_ylabel("TPR")
    a1.set_title("ROC (one-vs-rest) — %s" % label); a1.legend(fontsize=7)
    a2.set_xlabel("Recall"); a2.set_ylabel("Precision")
    a2.set_title("Precision-Recall (one-vs-rest) — %s" % label); a2.legend(fontsize=7)
    fig.tight_layout(); fig.savefig("%s/roc_pr_%s.png" % (out, label), dpi=200, bbox_inches="tight"); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir", default="data/pcap")
    ap.add_argument("--out", default="results/figs_artigo")
    ap.add_argument("--max-packets", type=int, default=None)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    print("extraindo...")
    Xn, y, counts, _t, _m, _mm = pipeline.extract_all(a.pcap_dir, max_packets=a.max_packets)
    itr, ite = pipeline.temporal_split(counts); y_te = y[ite]

    for idx, label in [(list(range(12)), "12feat"), (pipeline.CONTENT_EXT, "16feat")]:
        clf = XGBClassifier(**PARAMS); clf.fit(Xn[np.ix_(itr, idx)], y[itr])
        proba = clf.predict_proba(Xn[np.ix_(ite, idx)]); pred = proba.argmax(1)
        rep = classification_report(y_te, pred, target_names=CLASSES, digits=4, output_dict=True)
        macro = rep["macro avg"]["f1-score"]
        save_cm(y_te, pred, label, macro, a.out)
        save_roc_pr(y_te, proba, label, a.out)
        print("  %s: macro-F1 = %.4f  -> cm_%s.png, roc_pr_%s.png" % (label, macro, label, label))
    print("salvo em", os.path.abspath(a.out))


if __name__ == "__main__":
    main()
