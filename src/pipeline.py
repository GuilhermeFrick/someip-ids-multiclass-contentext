"""Pipeline canônico (promovido do notebook 07-resultados-artigo.ipynb) para módulo importável.

Reproduz, de forma headless, o experimento multiclasse canônico:
  PCAP cru -> extração (16 features, sem cabeçalho) -> split TEMPORAL 70/30 por arquivo
  -> XGBoost multi:softprob (5 classes) -> métricas por classe + macro-F1
  -> ablação 12x16 -> timing (fit, extração, inferência) -> results/metrics_temporal.json

Fonte única: usa os mesmos módulos de src/ (someip, bytemodel, extract, extract_ext),
sem duplicar código. `device` e `n_jobs` são configuráveis (CPU por padrão).

A instrumentação fina por estágio e por pacote (estilo Kim, 1 núcleo + cota) fica em
src/latency.py; aqui mantém-se o timing agregado idêntico ao do notebook.
"""
from __future__ import annotations

import json
import os
import platform
import time

import numpy as np

import labeler
from extract import fit_bytemodels, BENIGN_FILE, ATTACK_FILES, PCAP_DIR_DEFAULT, L  # noqa: F401
from extract_ext import extract_file, FEATURE_NAMES

CLASSES = ["normal", "dos", "fuzzy", "mitm_single", "mitm_multi"]
N = len(CLASSES)
CONTENT_EXT = list(range(16))   # as 16 features (12 do baseline + 4 propostas), sem cabeçalho

# FONTE ÚNICA dos hiperparâmetros do modelo. Todo script que treina deve importar
# daqui (`from pipeline import MODEL_PARAMS`) em vez de redeclarar, para que o
# modelo avaliado seja exatamente o mesmo que é embarcado no sensor em C++.
#
# Escolhidos por varredura em um conjunto de VALIDAÇÃO recortado de dentro do
# treino (split aninhado, preservando a ordem temporal), nunca no teste. O teste
# só foi usado para reportar, depois de retreinar no treino completo.
#
# Isso importa: uma varredura anterior, feita olhando o teste, elegia 50 rodadas
# com profundidade 4, que tinha o melhor teste (0,9695) e uma validação ruim
# (0,9418, sétimo lugar) — vantagem por sorte no conjunto de reporte.
#
# A configuração escolhida dá macro-F1 0,9689 no teste, contra 0,9640 das 300
# rodadas com profundidade 8 usadas antes, com 6,7x menos nós. O modelo maior
# sobreajustava, e a classe mais difícil (MITM-multi) era a que mais sofria:
# ela sobe de 0,8380 para 0,8580. Ver someip-testbench/experiments/model-sweep.
MODEL_ROUNDS = 25
MODEL_DEPTH = 8


def model_params(device: str = "cpu", n_jobs: int = -1) -> dict:
    """Hiperparâmetros do modelo. Única definição do projeto."""
    return dict(objective="multi:softprob", num_class=N,
                n_estimators=MODEL_ROUNDS, max_depth=MODEL_DEPTH,
                learning_rate=0.3, tree_method="hist", device=device,
                max_bin=256, n_jobs=n_jobs, eval_metric="mlogloss")


def machine_info() -> dict:
    info = {"platform": platform.platform(),
            "processor": platform.processor() or platform.machine(),
            "cpu_logical": os.cpu_count()}
    try:
        import psutil
        info["cpu_physical"] = psutil.cpu_count(logical=False)
        info["ram_gb"] = round(psutil.virtual_memory().total / 1e9, 1)
    except Exception:
        info["cpu_physical"] = None
        info["ram_gb"] = None
    return info


def extract_all(pcap_dir: str = PCAP_DIR_DEFAULT, alpha: float = 1.0, max_packets=None):
    """PCAP cru -> features normalizadas (min-max por coluna). Cronometrado.

    Returns: Xn (float32, N x 21), y (int64 multiclasse), counts (por arquivo),
             timing (dict), models, (xmin, xmax).
    """
    t0 = time.perf_counter()
    models, benign_ips = fit_bytemodels(pcap_dir, alpha, max_packets)
    t_fit = time.perf_counter() - t0

    files = [(BENIGN_FILE, labeler.NORMAL)] + list(ATTACK_FILES.items())
    Xparts, yparts, counts, t_ext = [], [], [], 0.0
    for fname, atk in files:
        path = os.path.join(pcap_dir, fname)
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        t0 = time.perf_counter()
        Xf, ymf, _ = extract_file(path, models, atk, benign_ips, max_packets)
        t_ext += time.perf_counter() - t0
        Xparts.append(np.asarray(Xf, dtype=np.float64))
        yparts.append(np.asarray(ymf, dtype=np.int64))
        counts.append(len(ymf))

    Xraw = np.concatenate(Xparts)
    y = np.concatenate(yparts)
    del Xparts, yparts
    xmin = Xraw.min(0)
    xmax = Xraw.max(0)
    rng = np.where(xmax > xmin, xmax - xmin, 1.0)
    Xn = ((Xraw - xmin) / rng).astype(np.float32)
    del Xraw

    timing = {"bytemodel_fit_s": float(t_fit),
              "extraction_total_s": float(t_ext),
              "extraction_us_per_pkt": float(t_ext / y.size * 1e6)}
    return Xn, y, counts, timing, models, (xmin, xmax)


def temporal_split(counts, frac: float = 0.70):
    """Primeiros `frac` cronológicos de cada arquivo -> treino; resto -> teste."""
    tr, te, s = [], [], 0
    for c in counts:
        cut = s + int(c * frac)
        tr.append(np.arange(s, cut))
        te.append(np.arange(cut, s + c))
        s += c
    return np.concatenate(tr), np.concatenate(te)


def _figures(out_dir, cm, cmn, y_te, proba, fnames, imp, order):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import roc_curve, auc, precision_recall_curve, average_precision_score
    from sklearn.preprocessing import label_binarize

    # matriz de confusão normalizada
    fig, ax = plt.subplots(figsize=(6.5, 5.5))
    im = ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(N)); ax.set_yticks(range(N))
    ax.set_xticklabels(CLASSES, rotation=45, ha="right"); ax.set_yticklabels(CLASSES)
    ax.set_xlabel("Predicted"); ax.set_ylabel("True"); ax.set_title("Confusion matrix (temporal split)")
    for i in range(N):
        for j in range(N):
            ax.text(j, i, f"{cmn[i,j]*100:.1f}%\n({cm[i,j]:,})", ha="center", va="center",
                    fontsize=7, color="white" if cmn[i, j] > 0.5 else "black")
    fig.colorbar(im, fraction=0.046, pad=0.04); fig.tight_layout()
    fig.savefig(f"{out_dir}/cm_temporal.png", dpi=200, bbox_inches="tight"); plt.close(fig)

    # ROC + PR (one-vs-rest)
    yb = label_binarize(y_te, classes=range(N))
    roc_auc, pr_ap = {}, {}
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
    for i, name in enumerate(CLASSES):
        fpr, tpr, _ = roc_curve(yb[:, i], proba[:, i]); a = auc(fpr, tpr); roc_auc[name] = float(a)
        s = max(len(fpr) // 2000, 1); ax1.plot(fpr[::s], tpr[::s], lw=1.6, label=f"{name} (AUC={a:.3f})")
        prec, rec, _ = precision_recall_curve(yb[:, i], proba[:, i])
        ap = average_precision_score(yb[:, i], proba[:, i]); pr_ap[name] = float(ap)
        s2 = max(len(rec) // 2000, 1); ax2.plot(rec[::s2], prec[::s2], lw=1.6, label=f"{name} (AP={ap:.3f})")
    ax1.plot([0, 1], [0, 1], "k--", lw=0.7); ax1.set_xlabel("False Positive Rate"); ax1.set_ylabel("True Positive Rate")
    ax1.set_title("ROC (one-vs-rest, temporal)"); ax1.legend(fontsize=8, loc="lower right")
    ax2.set_xlabel("Recall"); ax2.set_ylabel("Precision"); ax2.set_title("Precision-Recall (one-vs-rest, temporal)")
    ax2.legend(fontsize=8, loc="lower left"); fig.tight_layout()
    fig.savefig(f"{out_dir}/roc_pr_temporal.png", dpi=200, bbox_inches="tight"); plt.close(fig)

    # importância (gain)
    fig, ax = plt.subplots(figsize=(7, 5.5))
    ax.barh([fnames[i] for i in order], imp[order])
    ax.set_xlabel("Importancia (gain, XGBoost)"); ax.set_title("Importancia das 16 features (split temporal)")
    fig.tight_layout(); fig.savefig(f"{out_dir}/feature_importance.png", dpi=200, bbox_inches="tight"); plt.close(fig)
    return roc_auc, pr_ap


def train_eval(Xn, y, counts, device: str = "cpu", n_jobs: int = -1,
               out_dir: str = "results", make_figs: bool = True) -> dict:
    """Treina o modelo de 16 features, avalia (métricas + figuras), faz a ablação 12x16
    e mede o tempo de inferência agregado. Retorna o dicionário de métricas."""
    from sklearn.metrics import classification_report, confusion_matrix
    from xgboost import XGBClassifier
    os.makedirs(out_dir, exist_ok=True)

    params = model_params(device=device, n_jobs=n_jobs)
    X16 = Xn[:, CONTENT_EXT]
    fnames = [FEATURE_NAMES[i] for i in CONTENT_EXT]
    itr, ite = temporal_split(counts)
    y_te = y[ite]

    clf = XGBClassifier(**params)
    clf.fit(X16[itr], y[itr])
    clf.save_model(os.path.join(out_dir, "model_16.json"))   # artefato p/ o harness de latência
    proba = clf.predict_proba(X16[ite])
    y_pred = proba.argmax(1)
    rep = classification_report(y_te, y_pred, target_names=CLASSES, digits=4, output_dict=True)
    macro_f1 = rep["macro avg"]["f1-score"]
    acc = rep["accuracy"]

    cm = confusion_matrix(y_te, y_pred)
    cmn = cm / cm.sum(1, keepdims=True)
    score = clf.get_booster().get_score(importance_type="gain")
    imp = np.array([score.get(f"f{i}", 0.0) for i in range(len(CONTENT_EXT))])
    order = np.argsort(imp)
    roc_auc, pr_ap = ({}, {})
    if make_figs:
        roc_auc, pr_ap = _figures(out_dir, cm, cmn, y_te, proba, fnames, imp, order)
    feat_imp = {fnames[i]: float(imp[i]) for i in order[::-1]}

    # inferência agregada (lote) — timing fino por pacote fica em src/latency.py
    Xte = X16[ite]
    _ = clf.predict_proba(Xte[:2000])          # warm-up
    t0 = time.perf_counter(); _ = clf.predict_proba(Xte); inf_total = time.perf_counter() - t0
    inf_us = inf_total / Xte.shape[0] * 1e6

    # ablação 12 (núcleo) vs 16
    clf12 = XGBClassifier(**params)
    clf12.fit(X16[itr][:, :12], y[itr])
    pred12 = clf12.predict(X16[ite][:, :12])
    rep12 = classification_report(y_te, pred12, target_names=CLASSES, digits=4, output_dict=True)
    macro12 = rep12["macro avg"]["f1-score"]

    return {
        "split": "temporal_by_file_70_30",
        "params": dict(params),
        "test_counts": dict(zip(CLASSES, np.bincount(y_te, minlength=N).tolist())),
        "model_16feat": {
            "macro_f1": float(macro_f1), "accuracy": float(acc),
            "per_class": {c: {k: float(rep[c][k]) for k in ("precision", "recall", "f1-score")} for c in CLASSES},
            "roc_auc": roc_auc, "pr_ap": pr_ap, "feature_importance_gain": feat_imp},
        "ablation_12feat": {"macro_f1": float(macro12),
                            "per_class_f1": {c: float(rep12[c]["f1-score"]) for c in CLASSES}},
        "inference_us_per_pkt_batch": float(inf_us),
    }


def run(pcap_dir: str = PCAP_DIR_DEFAULT, out_dir: str = "results",
        device: str = "cpu", n_jobs: int = -1, make_figs: bool = True,
        max_packets=None) -> dict:
    """Experimento ponta a ponta; grava results/metrics_temporal.json e retorna o dict."""
    Xn, y, counts, timing, _models, _mm = extract_all(pcap_dir, max_packets=max_packets)
    res = train_eval(Xn, y, counts, device=device, n_jobs=n_jobs, out_dir=out_dir, make_figs=make_figs)
    # artefatos p/ o harness de latência (o modelo já foi salvo em train_eval)
    np.savez_compressed(os.path.join(out_dir, "bytemodels.npz"),
                        someip=_models["someip"].logP, sd=_models["sd"].logP, l4=_models["l4"].logP)
    np.save(os.path.join(out_dir, "minmax.npy"), np.vstack(_mm))
    json.dump(CONTENT_EXT, open(os.path.join(out_dir, "content_idx.json"), "w"))
    inf_us = res.pop("inference_us_per_pkt_batch")
    timing["inference_us_per_pkt"] = float(inf_us)
    timing["extraction_over_inference"] = float(timing["extraction_us_per_pkt"] / inf_us)
    out = {"machine": machine_info(), "timing": timing, **res}
    os.makedirs(out_dir, exist_ok=True)
    json.dump(out, open(os.path.join(out_dir, "metrics_temporal.json"), "w"), indent=2)
    return out
