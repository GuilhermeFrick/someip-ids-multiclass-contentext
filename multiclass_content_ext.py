"""IDS multiclasse (5 classes) com as features content_ext (sem header), para fechar a
comparação com o baseline Kim-12 (macro-F1 0,78).

content_ext = 12 do Kim + repeat_rate, someip_len, l4_len, src_payload_div (16 features).
Split 70/30 estratificado. Métricas por classe + matriz de confusão + ROC/PR.
Reproduzir: python src/multiclass_content_ext.py
"""
from __future__ import annotations

import json
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report, confusion_matrix, roc_curve, auc,
                             precision_recall_curve, average_precision_score)
from sklearn.preprocessing import label_binarize
from xgboost import XGBClassifier

CLASSES = ["normal", "dos", "fuzzy", "mitm_single", "mitm_multi"]
N = len(CLASSES)
SEED = 0
FIGDIR = "results/figuras"
CONTENT_EXT = list(range(12)) + [12, 13, 14, 16]   # sem header


def main():
    os.makedirs(FIGDIR, exist_ok=True)
    X = np.load("data/ours_ext/X.npz")["a"][:, CONTENT_EXT]
    y = np.load("data/ours_ext/y_multi.npz")["a"]
    print(f"dados: {X.shape} ({len(CONTENT_EXT)} features content_ext) classes={np.bincount(y).tolist()}")

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.30, random_state=SEED, stratify=y)
    clf = XGBClassifier(objective="multi:softprob", num_class=N, n_estimators=300, max_depth=8,
                        learning_rate=0.3, tree_method="hist", max_bin=256, n_jobs=-1,
                        eval_metric="mlogloss")
    print("treinando...")
    clf.fit(X_tr, y_tr)
    proba = clf.predict_proba(X_te)
    y_pred = proba.argmax(axis=1)

    rep = classification_report(y_te, y_pred, target_names=CLASSES, digits=4, output_dict=True)
    print("\n== content_ext multiclasse — por classe ==")
    for c in CLASSES:
        r = rep[c]
        print(f"  {c:12} P={r['precision']:.4f} R={r['recall']:.4f} F1={r['f1-score']:.4f}")
    print(f"  accuracy={rep['accuracy']:.4f}  macro-F1={rep['macro avg']['f1-score']:.4f}  "
          f"weighted-F1={rep['weighted avg']['f1-score']:.4f}")

    cm = confusion_matrix(y_te, y_pred)
    cmn = cm / cm.sum(axis=1, keepdims=True)
    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(N)); ax.set_yticks(range(N))
    ax.set_xticklabels(CLASSES, rotation=45, ha="right"); ax.set_yticklabels(CLASSES)
    ax.set_xlabel("Predito"); ax.set_ylabel("Verdadeiro")
    ax.set_title("Matriz de Confusão — content_ext (multiclasse)")
    for i in range(N):
        for j in range(N):
            ax.text(j, i, f"{cmn[i,j]*100:.1f}\n({cm[i,j]:,})", ha="center", va="center",
                    fontsize=7, color="white" if cmn[i, j] > 0.5 else "black")
    fig.colorbar(im, fraction=0.046, pad=0.04)
    plt.tight_layout(); plt.savefig(f"{FIGDIR}/matriz-confusao-content_ext.png", dpi=130); plt.close()

    yb = label_binarize(y_te, classes=range(N))
    rocaucs, praucs = {}, {}
    for i, name in enumerate(CLASSES):
        fpr, tpr, _ = roc_curve(yb[:, i], proba[:, i]); rocaucs[name] = float(auc(fpr, tpr))
        praucs[name] = float(average_precision_score(yb[:, i], proba[:, i]))
    print("ROC-AUC:", {k: round(v, 4) for k, v in rocaucs.items()})
    print("PR-AUC :", {k: round(v, 4) for k, v in praucs.items()})

    json.dump({"report": rep, "roc_auc": rocaucs, "pr_auc": praucs,
               "confusion_matrix": cm.tolist(), "classes": CLASSES, "features": "content_ext"},
              open("results/multiclass_content_ext.json", "w"), indent=2)
    print("\n-> results/multiclass_content_ext.json")


if __name__ == "__main__":
    main()
