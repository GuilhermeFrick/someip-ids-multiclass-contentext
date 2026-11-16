#!/usr/bin/env python3
"""Matriz entre domínios do detector C1 PUBLICADO (16 features), para as Tabelas XIII e XIV.

Cenários (teste sempre nos 30% finais de cada captura, pipeline.temporal_split):
  1. beta->beta    artefatos publicados como estão: results/features.npz (16 features já normalizadas
                   com results/minmax.npy, modelo de bytes results/bytemodels.npz) e results/model_16.json.
  2. beta->gama    o mesmo modelo, sem reajuste: features de gama com o modelo de bytes do Kim e a
                   normalização min-max do Kim.
  3. gama->gama    o mesmo PROCEDIMENTO em gama: modelo de bytes no benigno de gama (70% iniciais),
                   min-max do treino de gama, XGBClassifier com os hiperparâmetros do model_16.json,
                   treino nos 70% iniciais de cada captura.
  4. gama->beta    o modelo do cenário 3 aplicado, sem reajuste, aos 30% finais do Kim.

Rótulos: beta com o rótulo da C1 (regra por IP, labeler.py) e também por MAC; gama por MAC (scn.labels).
Saída: matriz_c1.json e matriz_c1.md.
"""
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
BASE = K.WORK
os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
sys.path.insert(0, os.path.join(R, "src"))
import pipeline  # noqa: E402

CL = pipeline.CLASSES
ORDEM = ["benign", "dos", "fuzzy1", "fuzzy2", "fuzzy3", "mitm_multi", "mitm_single"]
COLS = json.load(open(os.path.join(BASE, "feats", "cols.json")))
BMIDX = [1, 2, 3, 4, 5, 6]           # posições das 6 features de modelo de bytes entre as 16


def norm(X, xmin, xmax):
    rng = np.where(xmax > xmin, xmax - xmin, 1.0)
    return ((X.astype(np.float64) - xmin) / rng).astype(np.float32)


def carrega(dom, nome, bm):
    """16 features cruas (bm='kim': modelo de bytes do Kim; 'gama': as 6 de bytes trocadas por bmG)."""
    X = np.load(os.path.join(BASE, "feats", dom, nome + ".X.npy"), mmap_mode="r")
    A = np.array(X[:, :16], dtype=np.float32)
    if bm == "gama":
        A[:, BMIDX] = np.load(os.path.join(BASE, "feats", dom, nome + ".bmG.npy"))
    m = np.load(os.path.join(BASE, "feats", dom, nome + ".meta.npz"))
    return A, m["y_mac"].astype(np.int64), m["y_ip"].astype(np.int64)


def mede(pred_por, y_por, nomes):
    """pred_por / y_por: listas por captura (só a janela de teste)."""
    out = {"fp_por_captura": {}}
    for n, p, y in zip(nomes, pred_por, y_por):
        nor = y == 0
        out["fp_por_captura"][n] = {"fp": float(np.mean(p[nor] > 0)) if nor.any() else None,
                                    "normais": int(nor.sum()), "fp_quadros": int(np.sum(p[nor] > 0))}
    p, y = np.concatenate(pred_por), np.concatenate(y_por)
    rep = classification_report(y, p, labels=list(range(5)), target_names=CL, digits=4, output_dict=True,
                                zero_division=0)
    out["f1"] = {c: float(rep[c]["f1-score"]) for c in CL}
    out["recall"] = {c: float(rep[c]["recall"]) for c in CL}
    out["precisao"] = {c: float(rep[c]["precision"]) for c in CL}
    out["macro_f1"] = float(rep["macro avg"]["f1-score"])
    out["suporte"] = {c: int(rep[c]["support"]) for c in CL}
    out["fp_total"] = float(np.mean(p[y == 0] > 0))
    cm = np.bincount(y * 5 + p, minlength=25).reshape(5, 5)
    out["confusao"] = cm.tolist()
    return out


def main():
    res = {"notas": {}}
    # ---------- 1. beta -> beta (artefatos publicados) ----------
    b16 = xgb.Booster()
    b16.load_model(os.path.join(K.C1_ART, "model_16.json"))
    # a profundidade vem da ESTRUTURA das árvores: o campo max_depth da configuração salva no
    # artefato mostra o valor padrão (6), não o usado no treino (8; selecao_hiperparametros.json)
    arv = json.loads(b16.save_raw("json"))["learner"]["gradient_booster"]["model"]["trees"]

    def _prof(no, t):
        if t["left_children"][no] == -1:
            return 0
        return 1 + max(_prof(t["left_children"][no], t), _prof(t["right_children"][no], t))
    cfg = json.loads(b16.save_config())
    tp = cfg["learner"]["gradient_booster"]["tree_train_param"]
    hip = {"n_estimators": int(b16.num_boosted_rounds()), "max_depth": int(max(_prof(0, t) for t in arv)),
           "learning_rate": float(tp["eta"]), "max_bin": int(tp.get("max_bin", 256))}
    res["notas"]["hiperparametros_model_16"] = hip
    mm = np.load(os.path.join(K.C1_ART, "minmax.npy"))
    kmin, kmax = mm[0], mm[1]
    fpub = os.path.join(R, "results", "features.npz")
    if os.path.exists(fpub):
        # as features normalizadas que geraram o número publicado, quando estão no disco
        z = np.load(fpub, allow_pickle=True)
        Xn, yip, counts = z["Xn"], z["y"], [int(c) for c in z["counts"]]
        res["notas"]["beta_beta_fonte"] = "results/features.npz (publicado)"
    else:
        # sem o arquivo: a extração do Kim feita por extrai.py (modelo de bytes publicado),
        # normalizada com o minmax.npy publicado; é o mesmo cálculo do FeatureStreamer da C1
        partes, ys, counts = [], [], []
        for n in ORDEM:
            A, _, yi = carrega("kim", n, "kim")
            partes.append(norm(A, kmin, kmax))
            ys.append(yi)
            counts.append(len(A))
        Xn, yip = np.concatenate(partes), np.concatenate(ys)
        del partes, ys
        res["notas"]["beta_beta_fonte"] = "extrai.py + minmax.npy publicado"
    ini = np.concatenate([[0], np.cumsum(counts)])
    kim_te = {}
    for i, n in enumerate(ORDEM):
        a, c = ini[i], ini[i] + int(counts[i] * 0.7)
        meta = np.load(os.path.join(BASE, "feats", "kim", n + ".meta.npz"))
        assert np.array_equal(meta["y_ip"], yip[ini[i]:ini[i + 1]])
        kim_te[n] = {"X": Xn[c:ini[i + 1]], "y_ip": yip[c:ini[i + 1]],
                     "y_mac": meta["y_mac"][int(counts[i] * 0.7):].astype(np.int64)}
    pk = {n: b16.predict(xgb.DMatrix(kim_te[n]["X"])).argmax(1) for n in ORDEM}
    res["beta_beta"] = {"rotulo_ip": mede([pk[n] for n in ORDEM], [kim_te[n]["y_ip"] for n in ORDEM], ORDEM),
                        "rotulo_mac": mede([pk[n] for n in ORDEM], [kim_te[n]["y_mac"] for n in ORDEM], ORDEM)}
    print("beta->beta (IP): macro-F1 %.4f" % res["beta_beta"]["rotulo_ip"]["macro_f1"],
          {c: round(v, 4) for c, v in res["beta_beta"]["rotulo_ip"]["f1"].items()}, flush=True)
    # ---------- 2. beta -> gama ----------
    g = {n: carrega("gama", n, "kim") for n in ORDEM}
    gte = {}
    for n in ORDEM:
        A, ym, _ = g[n]
        c = int(len(A) * 0.7)
        gte[n] = (A[c:], ym[c:])
    pg = {n: b16.predict(xgb.DMatrix(norm(gte[n][0], kmin, kmax))).argmax(1) for n in ORDEM}
    res["beta_gama"] = mede([pg[n] for n in ORDEM], [gte[n][1] for n in ORDEM], ORDEM)
    print("beta->gama: macro-F1 %.4f FP %.4f" % (res["beta_gama"]["macro_f1"], res["beta_gama"]["fp_total"]), flush=True)
    del g, gte
    # ---------- 3. gama -> gama ----------
    g = {n: carrega("gama", n, "gama") for n in ORDEM}
    tr = [(A[:int(len(A) * 0.7)], ym[:int(len(A) * 0.7)]) for A, ym, _ in (g[n] for n in ORDEM)]
    te = {n: (g[n][0][int(len(g[n][0]) * 0.7):], g[n][1][int(len(g[n][0]) * 0.7):]) for n in ORDEM}
    Xtr = np.concatenate([t[0] for t in tr])
    ytr = np.concatenate([t[1] for t in tr])
    del tr, g
    gmin, gmax = Xtr.min(0).astype(np.float64), Xtr.max(0).astype(np.float64)
    par = pipeline.model_params(n_jobs=4)
    par.update(n_estimators=hip["n_estimators"], max_depth=hip["max_depth"], learning_rate=hip["learning_rate"],
               max_bin=hip["max_bin"])
    res["notas"]["parametros_treino_gama"] = {k: v for k, v in par.items()}
    clf = xgb.XGBClassifier(**par)
    clf.fit(norm(Xtr, gmin, gmax), ytr)
    del Xtr, ytr
    clf.save_model(os.path.join(BASE, "results", "model_16_gama.json"))
    np.save(os.path.join(BASE, "results", "minmax_gama.npy"), np.vstack([gmin, gmax]))
    pgg = {n: clf.predict(norm(te[n][0], gmin, gmax)) for n in ORDEM}
    res["gama_gama"] = mede([pgg[n] for n in ORDEM], [te[n][1] for n in ORDEM], ORDEM)
    print("gama->gama: macro-F1 %.4f FP %.4f" % (res["gama_gama"]["macro_f1"], res["gama_gama"]["fp_total"]), flush=True)
    del te
    # ---------- 4. gama -> beta ----------
    pgb, ybi, ybm = {}, {}, {}
    for n in ORDEM:
        A, ym, yi = carrega("kim", n, "gama")
        c = int(len(A) * 0.7)
        pgb[n] = clf.predict(norm(A[c:], gmin, gmax))
        ybi[n], ybm[n] = yi[c:], ym[c:]
    res["gama_beta"] = {"rotulo_ip": mede([pgb[n] for n in ORDEM], [ybi[n] for n in ORDEM], ORDEM),
                        "rotulo_mac": mede([pgb[n] for n in ORDEM], [ybm[n] for n in ORDEM], ORDEM)}
    print("gama->beta (IP): macro-F1 %.4f FP %.4f" % (res["gama_beta"]["rotulo_ip"]["macro_f1"],
                                                     res["gama_beta"]["rotulo_ip"]["fp_total"]), flush=True)
    json.dump(res, open(os.path.join(BASE, "matriz_c1.json"), "w"), indent=1)

    # ---------- tabelas ----------
    S = [("β→β", res["beta_beta"]["rotulo_ip"]), ("β→γ", res["beta_gama"]), ("γ→γ", res["gama_gama"]),
         ("γ→β", res["gama_beta"]["rotulo_ip"])]
    L = ["**Tabela XIII (FP em janela benigna, % dos quadros rotulados normais na janela de teste de cada captura)**", "",
         "| captura | " + " | ".join(s for s, _ in S) + " |", "|---|" + "---:|" * len(S)]
    for n in ORDEM:
        L.append("| %s | %s |" % (n, " | ".join("%.3f%%" % (100 * r["fp_por_captura"][n]["fp"]) for _, r in S)))
    L.append("| **todas** | %s |" % " | ".join("%.3f%%" % (100 * r["fp_total"]) for _, r in S))
    L += ["", "**Tabela XIV (F1 por classe e macro-F1)**", "",
          "| classe | " + " | ".join(s for s, _ in S) + " |", "|---|" + "---:|" * len(S)]
    for c in CL:
        L.append("| %s | %s |" % (c, " | ".join("%.4f" % r["f1"][c] for _, r in S)))
    L.append("| **macro-F1** | %s |" % " | ".join("%.4f" % r["macro_f1"] for _, r in S))
    L += ["", "**Recall por classe de ataque**", "", "| classe | " + " | ".join(s for s, _ in S) + " |",
          "|---|" + "---:|" * len(S)]
    for c in CL[1:]:
        L.append("| %s | %s |" % (c, " | ".join("%.4f" % r["recall"][c] for _, r in S)))
    S2 = [("β→β (MAC)", res["beta_beta"]["rotulo_mac"]), ("γ→β (MAC)", res["gama_beta"]["rotulo_mac"])]
    L += ["", "**Variante: β rotulado por MAC (mesmos modelos)**", "", "| | " + " | ".join(s for s, _ in S2) + " |",
          "|---|---:|---:|"]
    for n in ORDEM:
        L.append("| FP %s | %s |" % (n, " | ".join("%.3f%%" % (100 * r["fp_por_captura"][n]["fp"]) for _, r in S2)))
    for c in CL:
        L.append("| F1 %s | %s |" % (c, " | ".join("%.4f" % r["f1"][c] for _, r in S2)))
    L.append("| macro-F1 | %s |" % " | ".join("%.4f" % r["macro_f1"] for _, r in S2))
    for c in CL[1:]:
        L.append("| recall %s | %s |" % (c, " | ".join("%.4f" % r["recall"][c] for _, r in S2)))
    open(os.path.join(BASE, "matriz_c1.md"), "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
