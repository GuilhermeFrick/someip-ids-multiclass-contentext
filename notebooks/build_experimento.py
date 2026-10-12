"""Gera notebooks/experimento.ipynb — o experimento COMPLETO da C1 (IDS multiclasse SOME/IP):
ambiente -> dados -> detecção (acurácia + ablação 12x16) -> latência por estágio -> varredura
de cota de CPU -> resumo. O notebook é FINO: importa tudo de src/ (fonte única), sem duplicar.

Rode:  python notebooks/build_experimento.py   (gera notebooks/experimento.ipynb)
"""
import json
import os


def md(*lines):
    return {"cell_type": "markdown", "metadata": {}, "source": [l + "\n" for l in lines]}


def code(src):
    return {"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
            "source": [l + "\n" for l in src.strip("\n").split("\n")]}


CELLS = [
    md("# Experimento — IDS multiclasse para SOME/IP (C1)",
       "",
       "Notebook **autossuficiente** e **apresentável**: roda o experimento ponta a ponta",
       "importando o código de `src/` (fonte única). Etapas:",
       "1. Ambiente/máquina · 2. Dados (PCAPs) · 3. Detecção (acurácia + ablação 12×16)",
       "· 4. Latência por estágio (1 núcleo) · 5. Varredura de cota de CPU · 6. Resumo.",
       "",
       "Roda em CPU (ECU-like) ou GPU; os números de latência devem ser lidos em CPU, 1 núcleo."),

    code("""
# --- Bootstrap: garante repo + deps + src no path (funciona local, VM ou Colab) ---
import os, sys
REPO = "someip-ids-multiclass-contentext"
def in_repo(): return os.path.exists("run_experiment.py") and os.path.isdir("src")
if not in_repo() and os.path.basename(os.getcwd()) == "notebooks": os.chdir("..")
if not in_repo() and os.path.isdir(REPO): os.chdir(REPO)
if not in_repo():
    os.system("git lfs install; git clone https://github.com/GuilhermeFrick/%s.git" % REPO)
    os.chdir(REPO)
os.system("%s -m pip install -q -r requirements.txt pandas" % sys.executable)
sys.path.insert(0, os.path.join(os.getcwd(), "src"))
MAX_PACKETS = None      # None = dataset completo (14.2M); use ex. 50000 p/ um teste rápido
print("cwd:", os.getcwd(), "| repo ok:", in_repo(), "| MAX_PACKETS:", MAX_PACKETS)
"""),

    md("## 1. Ambiente / máquina"),
    code("""
import pipeline
MACHINE = pipeline.machine_info()
for k, v in MACHINE.items(): print(f"{k:14}: {v}")
DEVICE = "cuda" if __import__("shutil").which("nvidia-smi") else "cpu"
print("device        :", DEVICE)
"""),

    md("## 2. Dados — PCAPs do dataset (figshare)",
       "Tráfego SOME/IP normal + 4 cenários de ataque (DoS, Fuzzy, MITM single/multi), ~14,2 M pacotes."),
    code("""
if not os.path.exists("data/pcap/benign_traffic.pcap"):
    print("baixando PCAPs (~1.9 GB)..."); os.system("%s scripts/download_pcaps.py" % sys.executable)
print(sorted(os.listdir("data/pcap")) if os.path.isdir("data/pcap") else "AUSENTE")
"""),

    md("## 3. Detecção (acurácia)",
       "Extração das 16 features (sem cabeçalho) do PCAP cru → split **temporal** 70/30 →",
       "XGBoost `multi:softprob` (5 classes) → métricas por classe + macro-F1 + **ablação 12×16**.",
       "Salva `results/metrics_temporal.json` + figuras + artefatos (modelo/byte-models/min-max)."),
    code("""
OUT = pipeline.run(pcap_dir="data/pcap", out_dir="results", device=DEVICE,
                   n_jobs=-1, make_figs=True, max_packets=MAX_PACKETS)
m, ab = OUT["model_16feat"], OUT["ablation_12feat"]
print("macro-F1  16feat =", round(m["macro_f1"], 4),
      "| 12feat (ablação) =", round(ab["macro_f1"], 4),
      "| accuracy =", round(m["accuracy"], 4))
"""),
    code("""
# Tabela por classe (16 feat) + ablação (F1 12 vs 16)
import pandas as pd
rows = []
for c in pipeline.CLASSES:
    pc = m["per_class"][c]
    rows.append({"classe": c, "precision": pc["precision"], "recall": pc["recall"],
                 "F1 (16 feat)": pc["f1-score"], "F1 (12 feat)": ab["per_class_f1"][c]})
pd.DataFrame(rows).round(4)
"""),

    md("### Figuras (matriz de confusão, ROC/PR, importância das features)"),
    code("""
from IPython.display import Image, display
for png in ("cm_temporal.png", "roc_pr_temporal.png", "feature_importance.png"):
    p = os.path.join("results", png)
    if os.path.exists(p): display(Image(filename=p))
"""),

    md("## 4. Latência por estágio (1 núcleo, por pacote)",
       "Mede, pacote a pacote, os 4 estágios (layer → feature → classification → decision),",
       "amostrando pacotes (estilo Kim). Classificação medida de 2 formas: `inplace_predict`",
       "(realista) e `predict_proba` (referência do wrapper). Compara com o lote amortizado."),
    code("""
import latency, json, numpy as np
from bytemodel import ByteModel
from extract import L
from xgboost import XGBClassifier

d = np.load("results/bytemodels.npz")
def _bm(k, arr):
    bm = ByteModel(L[k]); bm.logP = arr; return bm
MODELS = {k: _bm(k, d[k]) for k in ("someip", "sd", "l4")}
MMX = np.load("results/minmax.npy"); CIDX = json.load(open("results/content_idx.json"))
CLF = XGBClassifier(); CLF.load_model("results/model_16.json")

LAT = latency.measure("data/pcap/benign_traffic.pcap", MODELS, CLF, CIDX, (MMX[0], MMX[1]),
                      n_samples=1000, warmup=2000)
json.dump(LAT, open("results/latency_sample.json", "w"), indent=2)
s = LAT["stages_us"]
import pandas as pd
tbl = pd.DataFrame([
    {"estágio": "layer (parse)",          "us/pkt": s["layer"]["mean_us"]},
    {"estágio": "feature",                "us/pkt": s["feature"]["mean_us"]},
    {"estágio": "classification (inplace)", "us/pkt": s["classification_inplace"]["mean_us"]},
    {"estágio": "classification (wrapper)", "us/pkt": s["classification_wrapper"]["mean_us"]},
    {"estágio": "decision (argmax)",      "us/pkt": s["decision"]["mean_us"]},
]).round(2)
print("end-to-end: %.1f us/pkt (%.0f pps) | extração %.1f | inferência %.1f us/pkt"
      % (LAT["end_to_end_us_per_pkt"], LAT["throughput_pps"],
         LAT["extraction_us_per_pkt"], LAT["inference_us_per_pkt"]))
print("inferência em LOTE (amortizada): %.2f us/pkt" % OUT["timing"]["inference_us_per_pkt"])
tbl
"""),

    md("## 5. Varredura de cota de CPU — 1 núcleo (Tabela 5, estilo Kim)",
       "Pin em 1 núcleo + cota de CPU variável (`systemd-run`). Requer `sudo`/systemd (roda na VM;",
       "em Colab pode não estar disponível)."),
    code("""
import os, json
os.system("bash scripts/cpu_quota.sh")
QPATH = "results/latency_quota.json"
if os.path.exists(QPATH):
    Q = json.load(open(QPATH))
    import pandas as pd
    dfq = pd.DataFrame([{"cota %": r["cpu_quota_pct"], "cpus": r["allowed_cpus"],
                         "e2e us/pkt": round(r["latency"]["end_to_end_us_per_pkt"], 1),
                         "pps": round(r["latency"]["throughput_pps"])} for r in Q])
    display(dfq)
else:
    print("varredura indisponível (sem systemd/sudo) — rode na VM.")
"""),
    code("""
# Curva latência x cota (1 núcleo)
if os.path.exists(QPATH):
    import matplotlib.pyplot as plt
    q1 = [r for r in Q if r["allowed_cpus"] == "0"]
    xs = [r["cpu_quota_pct"] for r in q1]
    ys = [r["latency"]["end_to_end_us_per_pkt"] for r in q1]
    plt.figure(figsize=(7, 4)); plt.plot(xs, ys, "o-")
    plt.xlabel("Cota de CPU (%) — 1 núcleo"); plt.ylabel("Latência end-to-end (us/pacote)")
    plt.title("Latência x cota de CPU (1 núcleo)"); plt.grid(True, alpha=0.3); plt.tight_layout()
    plt.savefig("results/latency_quota.png", dpi=200, bbox_inches="tight"); plt.show()
"""),

    md("## 6. Resumo"),
    code("""
print("=== DETECÇÃO (split temporal) ===")
print("  macro-F1 16 feat :", round(m["macro_f1"], 4))
print("  macro-F1 12 feat :", round(ab["macro_f1"], 4), "(ablação)")
print("  accuracy         :", round(m["accuracy"], 4))
print("=== LATÊNCIA (1 núcleo, por pacote) ===")
print("  extração         : %.1f us/pkt" % LAT["extraction_us_per_pkt"])
print("  inferência       : %.1f us/pkt (chamada unitária)" % LAT["inference_us_per_pkt"])
print("  end-to-end       : %.1f us/pkt (%.0f pps)" % (LAT["end_to_end_us_per_pkt"], LAT["throughput_pps"]))
print("  inferência lote  : %.2f us/pkt (amortizada)" % OUT["timing"]["inference_us_per_pkt"])
print("Artefatos em results/: metrics_temporal.json, latency_sample.json, latency_quota.json, *.png")
"""),
]

NB = {"cells": CELLS,
      "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                   "language_info": {"name": "python"}},
      "nbformat": 4, "nbformat_minor": 5}

if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "experimento.ipynb")
    json.dump(NB, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("gerado:", out, "|", len(CELLS), "células")
