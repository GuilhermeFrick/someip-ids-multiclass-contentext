"""Ambiente de teste para PCAPs gerados pelo someip-traffic-simulator.

Carrega um PCAP + seu ground truth (.labels.npy), extrai as features content_ext
(byte-models ajustados no tráfego NORMAL do próprio PCAP — domínio consistente),
treina/testa um XGBoost multiclasse e gera métricas + matriz de confusão.

Modos:
  # 1) auto-contido: 1 PCAP, split 70/30 (o tráfego gerado é coerente/aprendível?)
  python eval_pcap.py traces/dataset.pcap

  # 2) transfer / zero-day: treina num PCAP, testa em outro
  python eval_pcap.py traces/train_known.pcap --test-pcap traces/test_novel.pcap

  # 3) zero-day binário (ataque novo): normal-vs-ataque -> detecção do tipo inédito
  python eval_pcap.py traces/train_known.pcap --test-pcap traces/test_novel.pcap --binary

Ground truth: <pcap>.labels.npy (gerado pelo simulador). Rótulo = nome do ataque
(dos/fuzzy/mitm/replay/tamper/hwfailure/...) ou 'normal'.
"""
from __future__ import annotations

import argparse
import os
import sys

import numpy as np
import matplotlib.pyplot as plt   # backend Agg é setado em cm_plot (não força no import p/ notebooks)
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from xgboost import XGBClassifier

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from scapy.utils import RawPcapReader   # noqa: E402
import someip                            # noqa: E402
import extract as _ex                    # noqa: E402
import extract_ext                       # noqa: E402
from bytemodel import ByteModel          # noqa: E402

CONTENT_EXT = list(range(12)) + [12, 13, 14, 16]
# ataques "de processo" (semânticos) agrupados — comportamento parecido entre si
PROCESS = {"deleteRequest", "deleteResponse", "sendErrorOnError", "sendErrorOnEvent",
           "wrongInterface", "fakeClientID", "fakeResponse", "disturbTiming"}
ORDER = ["normal", "dos", "fuzzy", "mitm", "tamper", "replay", "hwfailure", "failure", "process"]


def map_label(s: str) -> str:
    if s == "normal":
        return "normal"
    return "process" if s in PROCESS else s


def fit_models_on_normal(pcap: str, labels: np.ndarray) -> dict:
    """Ajusta os byte-models nos pacotes NORMAIS do próprio PCAP (mesmo domínio)."""
    models = {k: ByteModel(_ex.L[k]) for k in _ex.L}
    i = 0
    for raw, _meta in RawPcapReader(pcap):
        p = someip.parse(raw)
        if p is not None and i < len(labels) and labels[i] == "normal":
            if p.pl_l4:
                models["l4"].update(p.pl_l4)
            if p.is_sd and p.pl_sd:
                models["sd"].update(p.pl_sd)
            elif p.pl_someip:
                models["someip"].update(p.pl_someip)
        i += 1
    for m in models.values():
        m.finalize()
    return models


def load_pcap(pcap: str, labels_path: str | None, models: dict | None):
    """Retorna (X content_ext, rótulos-string mapeados, models). Ajusta models se None."""
    labels_path = labels_path or (pcap + ".labels.npy")
    if not os.path.exists(labels_path):
        sys.exit(f"Ground truth não encontrado: {labels_path}\n"
                 f"(o simulador salva <pcap>.labels.npy junto do PCAP)")
    labels = np.load(labels_path, allow_pickle=True)
    if models is None:
        models = fit_models_on_normal(pcap, labels)
    X, _, _ = extract_ext.extract_file(pcap, models, attack_type=0, benign_ips=set())
    X = np.asarray(X, dtype=np.float64)[:, CONTENT_EXT]
    if len(X) != len(labels):
        print(f"  [aviso] {len(X)} features vs {len(labels)} rótulos — truncando ao menor")
        n = min(len(X), len(labels)); X, labels = X[:n], labels[:n]
    mapped = np.array([map_label(s) for s in labels])
    return X, mapped, models


def cm_plot(y_te, y_pred, classes, title, out_png):
    plt.switch_backend("Agg")   # salva em arquivo (uso via script/CLI)
    cm = confusion_matrix(y_te, y_pred, labels=range(len(classes)))
    cmn = cm / np.maximum(cm.sum(1, keepdims=True), 1)
    N = len(classes)
    fig, ax = plt.subplots(figsize=(1.3 * N + 3, 1.1 * N + 3))
    im = ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(N)); ax.set_yticks(range(N))
    ax.set_xticklabels(classes, rotation=45, ha="right"); ax.set_yticklabels(classes)
    ax.set_xlabel("Predito"); ax.set_ylabel("Verdadeiro"); ax.set_title(title)
    for a in range(N):
        for b in range(N):
            ax.text(b, a, f"{cmn[a, b]*100:.0f}", ha="center", va="center", fontsize=8,
                    color="white" if cmn[a, b] > 0.5 else "black")
    fig.colorbar(im, fraction=0.046, pad=0.04)
    os.makedirs(os.path.dirname(out_png) or ".", exist_ok=True)
    plt.tight_layout(); plt.savefig(out_png, dpi=130); plt.close()
    print("matriz de confusão salva em:", out_png)


def xgb(n_class):
    return XGBClassifier(objective="multi:softprob", num_class=n_class, n_estimators=300,
                         max_depth=6, learning_rate=0.3, tree_method="hist", n_jobs=-1,
                         eval_metric="mlogloss")


def report(y_te, y_pred, classes, title, out_png):
    print(f"\n== {title} ==")
    print(classification_report(y_te, y_pred, labels=range(len(classes)),
                                target_names=classes, digits=4, zero_division=0))
    print("macro-F1:", round(f1_score(y_te, y_pred, average="macro"), 4))
    cm_plot(y_te, y_pred, classes, title, out_png)


def run(pcap, labels, test_pcap, test_labels, binary, out_dir):
    print(f"[1] extraindo {pcap} ...")
    X, ymap, models = load_pcap(pcap, labels, None)

    if binary:
        ymap = np.where(ymap == "normal", "normal", "attack")

    if test_pcap is None:
        # ----- modo auto-contido: 70/30 -----
        classes = [c for c in (ORDER + ["attack"]) if (ymap == c).sum() >= 6]
        if len(classes) < 2:
            u = dict(zip(*[v.tolist() for v in np.unique(ymap, return_counts=True)]))
            print(f"\n[!] Este PCAP tem só {classes or list(u)} — não há o que classificar "
                  f"(precisa de >=2 classes).\n    Rótulos: {u}\n    Gere um cenário COM ataques "
                  f"(ex.: scenarios/dos.yaml ou scenarios/zeroday_train_known.yaml) e teste esse PCAP.")
            return
        cid = {c: i for i, c in enumerate(classes)}
        keep = np.isin(ymap, classes); X, ymap = X[keep], ymap[keep]
        y = np.array([cid[c] for c in ymap])
        print("classes:", {c: int((y == cid[c]).sum()) for c in classes})
        xmin, xmax = X.min(0), X.max(0)
        Xn = ((X - xmin) / np.where(xmax > xmin, xmax - xmin, 1.0)).astype(np.float32)
        Xtr, Xte, ytr, yte = train_test_split(Xn, y, test_size=0.30, random_state=0, stratify=y)
        clf = xgb(len(classes)); clf.fit(Xtr, ytr)
        report(yte, clf.predict(Xte), classes, f"IDS sobre {os.path.basename(pcap)} (70/30)",
               os.path.join(out_dir, "cm_selftrain.png"))
        return

    # ----- modo transfer / zero-day: treina em pcap, testa em test_pcap -----
    print(f"[2] extraindo {test_pcap} (mesmos byte-models do treino) ...")
    Xt, ymapt, _ = load_pcap(test_pcap, test_labels, models)
    if binary:
        ymapt = np.where(ymapt == "normal", "normal", "attack")

    classes = [c for c in (ORDER + ["attack"]) if (ymap == c).sum() >= 6]   # classes do TREINO
    cid = {c: i for i, c in enumerate(classes)}
    keep = np.isin(ymap, classes); X, ymap = X[keep], ymap[keep]
    ytr = np.array([cid[c] for c in ymap])
    # min-max ajustado no TREINO, aplicado no teste
    xmin, xmax = X.min(0), X.max(0); rng = np.where(xmax > xmin, xmax - xmin, 1.0)
    Xtr = ((X - xmin) / rng).astype(np.float32)
    Xte_full = ((Xt - xmin) / rng).astype(np.float32)

    clf = xgb(len(classes)); clf.fit(Xtr, ytr)

    if binary:
        # zero-day: o ataque NOVO aparece no teste; medimos detecção (vira 'attack'?)
        novel = [c for c in np.unique(ymapt) if c not in classes]   # tipos não vistos no treino
        attack_idx = cid.get("attack")
        print(f"\n== Zero-day binário: treino={list(cid)} | tipos no teste={list(np.unique(ymapt))} ==")
        pred = clf.predict(Xte_full)
        for c in np.unique(ymapt):
            mask = ymapt == c
            if c == "normal":
                fp = (pred[mask] == attack_idx).mean()
                print(f"  normal           -> falso alarme (predito ataque): {fp*100:.1f}%")
            else:
                det = (pred[mask] == attack_idx).mean()
                tag = " (NOVO/zero-day)" if c in novel else ""
                print(f"  {c:16}{tag:14} -> detecção (predito ataque): {det*100:.1f}%")
        return

    # transfer multiclasse: avalia só as classes presentes no treino
    keep_t = np.isin(ymapt, classes)
    yte = np.array([cid[c] for c in ymapt[keep_t]])
    report(yte, clf.predict(Xte_full[keep_t]), classes,
           f"Transfer: treino {os.path.basename(pcap)} -> teste {os.path.basename(test_pcap)}",
           os.path.join(out_dir, "cm_transfer.png"))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", help="PCAP de treino (ou único, no modo auto-contido)")
    ap.add_argument("--labels", default=None, help="ground truth do treino [<pcap>.labels.npy]")
    ap.add_argument("--test-pcap", default=None, help="PCAP de teste (modo transfer/zero-day)")
    ap.add_argument("--test-labels", default=None, help="ground truth do teste [<test-pcap>.labels.npy]")
    ap.add_argument("--binary", action="store_true", help="normal vs ataque (ideal p/ zero-day)")
    ap.add_argument("--out", default="results", help="pasta de saída das figuras [results]")
    a = ap.parse_args()
    run(a.pcap, a.labels, a.test_pcap, a.test_labels, a.binary, a.out)
